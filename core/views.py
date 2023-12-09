from rest_framework import permissions
from rest_framework.views import APIView
from .serializers import FetchNonceSerializer
from eth_account.messages import encode_defunct
from eth_account import Account
from .models import USDC_DECIMALS, User, Transaction, Fund, WhitelistDomain, WhitelistAddress, Chain, SCWAddress, RPCInfo
from eth_hash.auto import keccak
from rest_framework.response import Response
import requests, pickle, os
from web3 import Web3
from django.db import models
from eth_abi import encode, decode

web3 = Web3()

session = requests.Session()

try:
    if os.path.getsize('session_data.pickle') > 0:
        with open('session_data.pickle', 'rb') as f:
            cookies = pickle.load(f)
            session.cookies.update(cookies)
except FileNotFoundError:
    with open('session_data.pickle', 'wb') as f:
        pickle.dump(session.cookies, f)


# Create your views here.

class Login(APIView):
    """
    API to fetch user's nonce by address
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = FetchNonceSerializer


    def verify_ethereum_signature(self,message, signature, signer_address):
        # Convert the message to bytes
        # prefixed_message = f"\x19Ethereum Signed Message:\n{len(message)}{message}"
        message_bytes = encode_defunct(text=message)

        # Verify the signature
        is_valid = Account.recover_message(message_bytes, signature=signature).lower() == signer_address.lower()

        return is_valid
    
    def get(self, request):
        """
        Get Nonce 
        """
        try:
            user = User.objects.get(address=request.GET.get('address').lower()) 
        except User.DoesNotExist:
            return Response({'nonce': 0})
        return Response({'nonce': user.nonce})

    def post(self, request):
        """
        Post Nonce 
        """
        address = request.data['address'].lower()
        signature = request.data['signature']
        user = None
        try:
            user = User.objects.get(address=address)
        except User.DoesNotExist:
            user = User.objects.create(address=address, username=address)
            user.save()
        nonce = "0x" + keccak(str.encode(str(user.nonce))).hex()
        message = """Welcome to MultiLane.\nSign this message to login.\nNonce: {}""".format(nonce)
        result = self.verify_ethereum_signature(message, signature, address)
        tokens = {}
        if result:
            user.nonce += 1
            user.save()
            tokens = user.tokens()
        return Response({'result': result, 'tokens': tokens})

class Profile(APIView):
    """
    API to fetch user's profile
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        Get Profile 
        """
        user = request.user
        transaction = Transaction.objects.filter(user=user).order_by('-date')
        daily_transaction = Transaction.get_transaction_count_last_7_days(user)
        # get average of last 7 day transaction count which is average of all the values of above dictionary
        average = round(sum(daily_transaction.values()) / len(daily_transaction.values()),2)
        # get distribution of transaction on chain
        chain_distribution = Transaction.objects.filter(user=user).values('chain').annotate(count=models.Count('id'))
        # if chain_distribution is not empty then divide the count of each chain by total count and multiply by 100 to get percentage
        if chain_distribution:
            total = sum([t['count'] for t in chain_distribution])
            chain_distribution = [{'chain': t['chain'], 'count': round((t['count']/total)*100,2)} for t in chain_distribution]
        data = {
            'address': user.address,
            'bill': user.bill(),
            'balance': user.balance(),
            'transactions': [{'chain': t.chain, 'status': t.status, 'date': t.date.strftime("%d-%m-%Y %H:%M:%S"), 'amount': t.amount, 'link': t.link} for t in transaction],
            'daily_transaction_key': [k.strftime("%d-%m") for k, _ in daily_transaction.items()], # convert date object to string 'dd-mm-yyyy
            'daily_transaction_value': [v for _, v in daily_transaction.items()], # convert date object to string 'dd-mm-yyyy
            'average': average,
            'chain_distribution': chain_distribution,
        }
        return Response(data)
    
class TransactionView(APIView):
    """
    API to fetch user's transaction
    """
    permission_classes = [permissions.IsAuthenticated]

    """
    User will first call this API to get the signature from the server and the balances of the user is updated.
    """
    def post(self, request):
        """
        Post Transaction 
        """
        user = request.user
        chain = request.data['chain']
        amount = request.data['amount']
        status = 'Approved'
        if user.allowance() < amount:
            status = 'Rejected'
        else:
            user.expense += amount
            user.save()
        transaction = Transaction.objects.create(user=user, chain=chain, status=status,amount=amount)
        transaction.save()
        return Response({'result': True})

    def patch(self, request):
        """
        Patch Transaction 
        """
        user = request.user
        link = request.data['link']
        transaction = Transaction.objects.get(id=request.data['id'])
        if user.id != transaction.user.id:
            return Response({'result': False})
        transaction.link = link
        transaction.save()
        return Response({'result': True})


class ManageFunds(APIView):
    """
    API to fetch user's profile
    """
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        """
        Get Profile 
        """
        user = request.user
        funds = Fund.objects.filter(user=user).order_by('-date')
        data = {
            'bill': user.bill(),
            'balance': user.balance(),
            'fund': [{'type': f.type, 'status': f.status, 'date': f.date.strftime("%d-%m-%Y %H:%M:%S"), 'amount': round(f.amount/10**USDC_DECIMALS, 2), 'link': f.link} for f in funds],
        }
        return Response(data)

    def post(self, request):
        """
        Post Funds 
        """
        user = request.user
        amount = request.data['amount']
        status = request.data.get('status', 'Approved')
        if status == 'Approved':
            if request.data['type'].lower() == 'deposit':
                user.deposit += int(amount)
            elif request.data['type'].lower() == 'withdraw':
                user.deposit -= int(amount)
            elif request.data['type'].lower() == 'bill payment':
                user.paid += int(amount)
            user.save()
        funds = Fund.objects.create(user=user, type=request.data['type'],status=status,amount=amount, link=request.data['link'])
        funds.save()
        return Response({'result': True})

class Withdraw(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """
        Post Funds 
        """

        if request.user.is_authenticated:
            user = request.user
            address = user.address
        else:
            try:
                user = User.objects.get(address=request.data['address'].lower())
                address = user.address
            except User.DoesNotExist:
                scw_address = SCWAddress.objects.get(address=request.data['address'].lower())
                user = scw_address.user
                address = scw_address.address
        amount = int(request.data['amount'])
        if amount > user.balance()*10**USDC_DECIMALS:
            return Response({'result': False})
        else:
            hex_value = (web3.to_hex(web3.solidity_keccak(['address', 'uint256'], [web3.to_checksum_address(address), amount])))
            message = encode_defunct(hexstr=hex_value)
            signautre = (web3.eth.account.sign_message(message, private_key=os.environ.get('PRIVATE_KEY')))
            return Response({'result': True, 'signature': signautre.signature.hex()})

class BillPay(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        """
        Post Funds 
        """
        amount = int(request.data['amount'])
        hex_value = (web3.to_hex(web3.solidity_keccak(['address', 'uint256'], [web3.to_checksum_address(user.address), amount])))
        message = encode_defunct(hexstr=hex_value)
        signautre = (web3.eth.account.sign_message(message, private_key=os.environ.get('PRIVATE_KEY')))
        return Response({'result': True, 'signature': signautre.signature.hex()})


class ProfileConfiguration(APIView):
    """
    API to fetch user's profile configuration
    """
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        """
        Get Chains
        """
        chain = Chain.objects.all()
        domain = WhitelistDomain.objects.filter(user=request.user)
        address = WhitelistAddress.objects.filter(user=request.user)
        scw_address = SCWAddress.objects.filter(user=request.user)
        scw_address = {s.chain.chain_id: s.address for s in scw_address}
        address = {a.chain.chain_id: {'address': a.address, 'value': a.value} for a in address}
        data = {
            'name': request.user.first_name,
            'user_address': request.user.address,
            'all_address': request.user.all_address,
            'all_domain': request.user.all_domain,
            'domain': [d.domain for d in domain],
            'address': address,
            'chains': [{'name': c.name, 'chain_id': c.chain_id} for c in chain],
            'scw_address': scw_address,
        }
        return Response(data)


    def post(self, request):
        """
        Post Profile updates 
        """
        user = request.user
        user.first_name = request.data['name']
        user.all_address = request.data['all_address']
        user.all_domain = request.data['all_domain']
        user.save()
        for c in request.data.get('chain', []):
            chain = Chain.objects.get(chain_id=c['chain_id'])
            scw,_ = SCWAddress.objects.get_or_create(user=user, chain=chain)
            scw.address = c['address']
            scw.save()

        for d in request.data.get('domain', []) :
            domain,_ = WhitelistDomain.objects.get_or_create(user=user, domain=d)
            domain.domain = d
            domain.save()

        for a in request.data.get('address', []) :
            if not a.get('address'): continue
            chain = Chain.objects.get(chain_id=a['chain_id'])
            address,_ = WhitelistAddress.objects.get_or_create(user=user, chain=chain, address=a['address'])
            address.value = a['value']
            address.save()
        return Response({'result': True})

class ProfilePublic(APIView):
    """
    API to fetch user's profile configuration. This API is consumed by the chrome extension
    """
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        """
        Get Chains
        """
        user = User.objects.get(address=request.GET.get('address').lower())
        chain = Chain.objects.get(chain_id=request.GET.get('chain_id'))
        scw_address = SCWAddress.objects.get(user=user, chain=chain)
        data = {
            'balance': user.balance(),
            'scw_address': scw_address.address,
        }
        return Response(data)

class RPCBalance(APIView):
    permission_classes = [permissions.AllowAny]

    @staticmethod
    def convert(data, chain_id, user):
        chain = Chain.objects.filter(chain_id=chain_id)
        if not chain.exists():
            return data
        chain = chain.first()
        usdc_address = chain.usdc_address
        values = decode(['address[]', 'uint256[]'], bytes.fromhex(data['result'].replace('0x','')))
        modifided_values = [] 
        for i,address in enumerate(values[0]):
            if address.lower() == "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":
                modifided_values.append(10**17) # Fake value for ETH so that UI allows to trigger transaction
            if address.lower() == usdc_address.lower():
                modifided_values.append(int(user.balance()*10**USDC_DECIMALS))
            else:
                modifided_values.append(values[1][i])
        bytes_value = encode(['address[]', 'uint256[]'], (values[0],modifided_values))
        hex_value = bytes_value.hex()
        data['result'] = "0x" + hex_value 
        return data

    @staticmethod
    def get_chain_id(url):
        rpc_info, created = RPCInfo.objects.get_or_create(url=url)
        if not created:
            return rpc_info.rpc_chain_id
        data = session.post(url, json={"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1})
        # convert chain id to int from hex
        chain_id = int(data.json()['result'], 16)
        rpc_info.rpc_chain_id = chain_id
        rpc_info.save()
        # save session info to pickle file
        with open('session_data.pickle', 'wb') as f:
            pickle.dump(session.cookies, f)
        return chain_id

    def post(self, req):
        url = req.GET.get('url')
        # use req.session to make the api call
        headers = {'Cookie': f'sessionid={req.session.session_key}'}
        data = session.post(url, json=req.data, headers=headers)
        chain_id = self.get_chain_id(url)
        try:
            chain = Chain.objects.get(chain_id=chain_id)
        except Chain.DoesNotExist:
            return Response(data.json())
        address = "0x" + req.data['params'][0]['data'][-40:]
        scw_user = SCWAddress.objects.filter(address=address.lower(), chain=chain)
        if scw_user.exists():
            user = scw_user.first().user
            modifided_data = self.convert(data.json(), chain_id, user)
            return Response(modifided_data)
        else:
            return Response(data.json())

class FetchSCW(APIView):
    """
    Public API to fetch user's scw address
    """
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        """
        Get SCW Address
        """
        try:
            user = User.objects.get(address=request.GET.get('address').lower())
        except User.DoesNotExist:
            return Response({'scw_address': ''})
        chain = Chain.objects.get(chain_id=request.GET.get('chain_id'))
        scw_address = SCWAddress.objects.get(user=user, chain=chain)
        data = {
            'scw_address': scw_address.address,
        }
        return Response(data)

class ChainAddress(APIView):
    """
    API is used to fetch usdc address of all the chains
    """
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        """
        Get USDC Address
        """
        chain = Chain.objects.all()
        usdc = {c.chain_id: c.usdc_address for c in chain}
        multilane = {c.chain_id: c.multilane_address for c in chain}
        return Response({'usdc': usdc, 'multilane': multilane})

class BillTransaction(APIView):
    def post(self, request):
        """
        Post Transaction 
        """
        scw_address = request.data['address']
        scw = SCWAddress.objects.get(scw_address=scw_address)
        user = scw.user
        chain_id = request.data['chain_id']
        chain = Chain.objects.get(chain_id=chain_id)
        amount = request.data['amount']
        status = 'Approved'
        if user.allowance() < amount:
            status = 'Rejected'
        else:
            user.expense += amount
            user.save()
        transaction = Transaction.objects.create(user=user, chain=chain, status=status,amount=amount, link=request.data['link'])
        transaction.save()
        return Response({'result': True})