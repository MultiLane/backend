from rest_framework import serializers

# Serializers to fetch nonce using address
class FetchNonceSerializer(serializers.Serializer):
    address = serializers.CharField(max_length=255)