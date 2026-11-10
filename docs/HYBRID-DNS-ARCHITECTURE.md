# Eliminating Private DNS Split-Brain in Hub-and-Spoke Topologies

Prohibits spoke subscriptions from provisioning local `privatelink.*` zones and enforces central hub registration via Azure Policy `DeployIfNotExists` (DINE).
