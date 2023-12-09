from django.urls import path
from .views import Login, Profile, TransactionView, ManageFunds

urlpatterns = [
    path('login/', Login.as_view(), name='login'),
    path('profile/', Profile.as_view(), name='profile'),
    path('transaction/', TransactionView.as_view(), name='transaction'),
    path('funds/', ManageFunds.as_view(), name='funds'),
]