from django.contrib import admin
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Transaction, Fund, Chain, SCWAddress, RPCInfo

class CustomUserAdmin(UserAdmin):
    model = User

    list_display = ('username', 'balance')
    list_filter = ('is_active', 'is_staff', 'is_superuser')
    fieldsets = (
        (None, {'fields': ('username', 'expense','deposit','paid','email', 'address','password')}),
        ('Permissions', {'fields': ('is_staff', 'is_active',
         'is_superuser', 'groups', 'user_permissions')}),
        ('Dates', {'fields': ('last_login', 'date_joined')})
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'is_staff', 'is_active')}
         ),
    )
    search_fields = ('email',)
    ordering = ('email',)


class TransactionAdmin(admin.ModelAdmin):
    list_display = ('user', 'chain', 'status', 'date', 'amount', 'link')
    list_filter = ('status', 'date')
    search_fields = ('user__email', 'user__address')

class RPCInfoAdmin(admin.ModelAdmin):
    list_display = ('url', 'rpc_chain_id')

class FundsAdmin(admin.ModelAdmin):
    list_display = ('user',)
    search_fields = ('user__email', 'user__address')

class ChainAdmin(admin.ModelAdmin):
    list_display = ('name', 'chain_id')
    search_fields = ('name', 'chain_id')

admin.site.register(User, CustomUserAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(Fund, FundsAdmin)
admin.site.register(Chain, ChainAdmin)
admin.site.register(SCWAddress)
admin.site.register(RPCInfo, RPCInfoAdmin)