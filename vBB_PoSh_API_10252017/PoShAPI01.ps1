# Testing with a cool, openly available API
$apiRoot = Invoke-RestMethod -Uri 'https://swapi.co/api/' -Method Get
$apiRoot

# Continuing to explore this API 
$speciesApi = Invoke-RestMethod -Uri $apiRoot.Species -Method Get
$speciesApi
$species = $speciesApi | Select-Object -ExpandProperty Results 
$species
$species | Get-Random
