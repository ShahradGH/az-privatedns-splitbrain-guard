param location string = resourceGroup().location
resource resolver 'Microsoft.Network/dnsResolvers@2022-07-01' = {
  name: 'dnspr-hub-central'
  location: location
  properties: { virtualNetwork: { id: '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub' } }
}
