from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
USDC_DECIMALS = settings.USDC_DECIMALS


class User(AbstractUser):
    address = models.CharField(max_length=255, unique=True)
    nonce = models.IntegerField(default=0)
    expense = models.IntegerField(default=0)
    paid = models.IntegerField(default=0)
    deposit = models.IntegerField(default=0)
    all_address = models.BooleanField(default=True)
    all_domain = models.BooleanField(default=True)
    # USERNAME_FIELD = 'address'

    def __str__(self):
        return self.address

    def save(self, *args, **kwargs):
        self.address = self.address.lower()
        super().save(*args, **kwargs)

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
    
    def allowance(self):
        return self.balance - (self.expense + self.paid)

    def bill(self):
        return round((self.expense - self.paid)/10**USDC_DECIMALS, 2)
    
    def balance(self):
        return round((self.deposit - (self.expense - self.paid))/10**USDC_DECIMALS, 2)
