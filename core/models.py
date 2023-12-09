from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
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

class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    chain = models.CharField(max_length=255)
    status = models.CharField(max_length=255, choices=(('Approved', 'Approved'), ('Rejected', 'Rejected'), ('Pending', 'Pending')), default='pending')
    date = models.DateTimeField()
    amount = models.IntegerField(default=0)
    link = models.CharField(max_length=500, blank=True, null=True)

    def save(self, *args, **kwargs):
        # If date is not set, set it to the current date and time
        if not self.date:
            self.date = timezone.now()
        super().save(*args, **kwargs)


    
    def get_transaction_count_last_7_days(user):
        # Calculate the date 7 days ago from today
        seven_days_ago = timezone.now() - timedelta(days=7)

        # Query transactions within the last 7 days
        transactions_last_7_days = Transaction.objects.filter(user=user,date__gte=seven_days_ago)

        # Create a dictionary to store transaction counts for each day
        transaction_counts = {}

        # Iterate over the transactions and count them for each day
        for transaction in transactions_last_7_days:
            transaction_date = transaction.date.date()  # Extract the date part
            transaction_counts[transaction_date] = transaction_counts.get(transaction_date, 0) + 1

        # Fill in missing dates with zero counts
        for day_offset in range(7):
            date = (timezone.now() - timedelta(days=day_offset)).date()
            transaction_counts.setdefault(date, 0)

        # Sort the dictionary by date
        sorted_transaction_counts = dict(sorted(transaction_counts.items()))

        return sorted_transaction_counts

    def __str__(self):
        return self.user.address

class Fund(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type = models.CharField(max_length=255, choices=(('Deposit', 'Deposit'), ('Withdraw', 'Withdraw'), ('Bill Payment', 'Bill Payment')), default='Deposit')
    amount = models.IntegerField(default=0)
    date = models.DateTimeField()
    link = models.CharField(max_length=500, blank=True, null=True)
    status = models.CharField(max_length=255, choices=(('Approved', 'Approved'), ('Rejected', 'Rejected'), ('Pending', 'Pending')), default='pending')

    def save(self, *args, **kwargs):
        # If date is not set, set it to the current date and time
        if not self.date:
            self.date = timezone.now()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.user.address

class Chain(models.Model):
    name = models.CharField(max_length=255)
    chain_id = models.IntegerField(default=0, unique=True)
    usdc_address = models.CharField(max_length=66, blank=True, null=True)
    mailbox_address = models.CharField(max_length=66, blank=True, null=True)
    multilane_address = models.CharField(max_length=66, blank=True, null=True)
    explorer = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.name

    def __save__(self, *args, **kwargs):
        self.usdc_address = self.usdc_address.lower()
        self.mailbox_address = self.mailbox_address.lower()
        self.multilane_address = self.multilane_address.lower()
        super().save(*args, **kwargs)

class SCWAddress(models.Model):
    address = models.CharField(max_length=255)
    chain = models.ForeignKey(Chain, on_delete=models.SET_NULL, null=True)
    nonce = models.IntegerField(default=0)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.address

class WhitelistAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    chain = models.ForeignKey(Chain, on_delete=models.SET_NULL, null=True)
    address = models.CharField(max_length=255)
    value = models.IntegerField(default=0)

    def __str__(self):
        return self.address

class WhitelistDomain(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    domain = models.CharField(max_length=255)

    def __str__(self):
        return self.domain

class RPCInfo(models.Model):
    """
    This acts like a cache for RPC information. It is used to store the chain id of the chain
    """
    url = models.CharField(max_length=255, blank=True, null=True)
    rpc_chain_id = models.IntegerField(default=0)

    def __str__(self):
        return self.url