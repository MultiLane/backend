from django.urls import path
from .views import Login, Profile, TransactionView, ManageFunds, Withdraw, \
    BillPay, ProfileConfiguration, ProfilePublic, RPCBalance, FetchSCW, ChainAddress

urlpatterns = [
    path('login/', Login.as_view(), name='login'),
    path('profile/', Profile.as_view(), name='profile'),
    path('profile/public/', ProfilePublic.as_view(), name='profile_public'),
    path('profile/configuration/', ProfileConfiguration.as_view(), name='profile_configuration'),
    path('transaction/', TransactionView.as_view(), name='transaction'),
    path('funds/', ManageFunds.as_view(), name='funds'),
    path('withdraw/', Withdraw.as_view(), name='withdraw'),
    path('billpay/', BillPay.as_view(), name='billpay'),
    path('rpc/balance/', RPCBalance.as_view(), name='balance'),
    path('scw/address/', FetchSCW.as_view(), name='scw_address'),
    path('chain/address/', ChainAddress.as_view(), name='usdc_address'),
]