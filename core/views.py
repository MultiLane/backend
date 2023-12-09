from rest_framework import permissions
from rest_framework.views import APIView
from .serializers import FetchNonceSerializer
from eth_account.messages import encode_defunct
from eth_account import Account
from .models import User, Transaction, Fund
from eth_hash.auto import keccak
from rest_framework.response import Response

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
            'fund': [{'type': f.type, 'status': f.status, 'date': f.date.strftime("%d-%m-%Y %H:%M:%S"), 'amount': f.amount, 'link': f.link} for f in funds],
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
