$VerbosePreference = "Continue"
. "C:\cloud-automation\secrets.ps1"

Function Get-ServiceCatalog {
   try {
      return (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" =  @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to retrieve service catalog `n $($_.Exception.Message)"
   }
}


Function Get-DevicesInEnvironment {
   param (
      [string[]]$dataCenter,
      [string[]]$environmentGuid
   )
   $returnValue = @()
   $servers = @()
   $localValue = @()
   $availableDCs = ($catalog.access.serviceCatalog | Where-Object { $_.name -eq "cloudServersOpenstack" }).endpoints.region
   $dataCenterArray = ($availableDCs -notmatch $dataCenter)
   
   $uri = (($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $dataCenter).publicURL
   try {
      $localServers = ((Invoke-RestMethod -Uri $($uri + "/servers/detail") -Method GET -Headers $AuthToken -ContentType application/json).servers)
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to get list of servers `n $($_.Exception.Message)`n $uri"
   }
   foreach($environment in $environmentGuid) {
      if ( ($localServers.metadata | ? { $_ -like "*environmentGuid*"}).count -ne 0 )
      {
         $localValue += $localServers | ? {$_.metadata.environmentGuid -like $environment}
      }
      else
      {
         $localValue = $null
      }
   }
   
   foreach($dc in $dataCenterArray) {
      $uri = (($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $dc).publicURL
      try {
         $servers += ((Invoke-RestMethod -Uri $($uri + "/servers/detail") -Method GET -Headers $AuthToken -ContentType application/json).servers)
      }
      catch {
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to retrieve list of servers `n $($_.Exception.Message) `n $uri"
      }
   }
   foreach($environment in $environmentGuid) {
      if ( ($servers.metadata | ? { $_ -like "*environmentGuid*"}).count -ne 0 )
      {
         $returnvalue += $servers | ? {$_.metadata.environmentGuid -like $environment}
      }
      else
      {
         $returnvalue = $null
      }
      foreach($value in $returnValue) {
         write-verbose "Get-DevicesInEnvironment $value"
      }
      
   }
   return @{"remoteServers" = $returnValue; "localServers" = $localValue}
}

Function Get-CloudLoadBalancers {
   param (
      [string]$loadBalancerName,
      [string]$dataCenter
   )
   $uri = ((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers")
   try {
      $loadBalancer = (((Invoke-RestMethod -Uri $uri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName}).id
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Get-CloudLoadBalancers:Failed to retrieve load balancer information `n $uri `n $($_.Exception.Message)"
   }
   if($loadBalancer) {
      $uri = ($uri, $loadBalancer, "nodes" -join '/')
      try {
         $serversInPool = (Invoke-RestMethod -Uri $uri -Method Get -Headers $AuthToken -ContentType application/json)
      }
      catch {
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Get-CloudLoadBalancers:Failed to retrieve nodes in load balancer pool `n $($_.Exception.Message)"
      }
      $nodeAddresses = @()
      foreach($serverInPool in $serversInPool.nodes) {
         $nodeAddresses += $serverInPool.address
      }
   }
   
   return $nodeAddresses
}


Function Get-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$loadBalancerName,
      [uint32]$port,
      [string]$protocol,
      [string[]]$nodes,
      [string]$dataCenter,
      [string]$hostHeader,
      [string]$path,
      [uint32]$attemptsBeforeDeactivation,
      [uint32]$delay,
      [uint32]$timeout,
      [string]$statusRegex,
      [string]$type,
      [string]$algorithm
   )
   @{
        loadBalancerName = $loadBalancerName
        port = $port
        protocol = $protocol
        nodes = $nodes
        dataCenter = $dataCenter
        hostHeader = $hostHeader
        path = $path
        attemptsBeforeDeactivation = $attemptsBeforeDeactivation
        delay = $delay
        timeout = $timeout
        statusRegex = $statusRegex
        type = $type
    }
}

Function Test-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$loadBalancerName,
      [uint32]$port,
      [string]$protocol,
      [string[]]$nodes,
      [string]$dataCenter,
      [string]$hostHeader,
      [string]$path,
      [uint32]$attemptsBeforeDeactivation,
      [uint32]$delay,
      [uint32]$timeout,
      [string]$statusRegex,
      [string]$type,
      [string]$algorithm
   )
   $Global:catalog = Get-ServiceCatalog
   $Global:AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $uri = ((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers")
   try {
      $loadBalancerinfo = (((Invoke-RestMethod -Uri $uri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName})
      $loadBalancer = ($loadBalancerinfo).id
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Test-TargetResource:Failed to retrieve load balancer information `n $($_.Exception.Message)"
   }
   if(($loadBalancer) -eq $null) {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Information -EventId 1000 -Message "Load Balancer $loadBalancerName does not exist"
      return $false
   }
   try {
      $loadBalancerMonitorInfo = (Invoke-RestMethod -Uri $($uri, $loadBalancer, "healthmonitor" -join '/') -Method Get -Headers $AuthToken -ContentType application/json).healthMonitor
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Test-TargetResource:Failed to retrieve load balancer Monitoring information `n $uri `n $($_.Exception.Message)"
   }
   $nodeAddresses = Get-CloudLoadBalancers -loadBalancerName $loadBalancerName -dataCenter $dataCenter
   $servers = Get-DevicesInEnvironment -environmentGuid $nodes -dataCenter $dataCenter
   $publicIps = $servers.remoteServers.addresses.public.addr | ? {$_ -notmatch '^10\.' -and $_ -notmatch '^127\.' -and $_ -notmatch '^2001:'}
   $privateIps = $servers.localServers.addresses.private.addr
   $allNodeIps = @()
   $allNodeIps += $publicIps
   $allNodeIps += $privateIps
   $addNodeIps = @()
   $removeNodeIps = @()
   
   foreach($allNodeIp in $allNodeIps) {
      if($nodeAddresses -notcontains $allNodeIp) {
         $addNodeIps += $allNodeIp
      }
   }
   
   foreach($nodeAddress in $nodeAddresses) {
      if($allNodeIps -notcontains $nodeAddress) {
         $removeNodeIps += $nodeAddress
      }
   }
   if($addNodeIps) {
      return $false
   }
   if($removeNodeIps) {
      return $false
   }
   if($loadBalancerinfo.protocol -ne $protocol) {
      Write-Verbose "protocoal"
      return $false
   }
   if($loadBalancerinfo.port -ne $port) {
      Write-Verbose "port"
      return $false
   }
   if($loadBalancerinfo.algorithm -ne $algorithm) {
      Write-Verbose "algorithm"
      return $false
   }
   if($loadBalancerMonitorInfo.type -ne $type) {
      Write-Verbose "type"
      return $false
   }
   if($type -ne "Connect") {
      if($loadBalancerMonitorInfo.attemptsBeforeDeactivation -ne $attemptsBeforeDeactivation) {
         Write-Verbose "attempts"
         return $false
      }
      if($loadBalancerMonitorInfo.delay -ne $delay) {
         Write-Verbose "delay"
         return $false
      }
      if($loadBalancerMonitorInfo.path -ne $path) {
         Write-Verbose "path"
         return $false
      }
      if($loadBalancerMonitorInfo.timeout -ne $timeout) {
         Write-Verbose "timeout"
         return $false
      }
      if($loadBalancerMonitorInfo.statusRegex -ne $statusRegex) {
         Write-Verbose "statusRegex"
         return $false
      }
      if($loadBalancerMonitorInfo.hostHeader -ne $hostHeader) {
         Write-Verbose "hostHeader"
         return $false
      }
   }
   if($type -eq "HTTP" -or $type -eq "HTTPS") {
      if($loadBalancerMonitorInfo.attemptsBeforeDeactivation -ne $attemptsBeforeDeactivation) {
         return $false
      }
      if($loadBalancerMonitorInfo.delay -ne $delay) {
         Write-Verbose "http delay"
         return $false
      }
      if($loadBalancerMonitorInfo.timeout -ne $timeout) {
         Write-Verbose "http timeout"
         return $false
      }
   }
   return $true
}

Function Set-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$loadBalancerName,
      [uint32]$port,
      [string]$protocol,
      [string[]]$nodes,
      [string]$dataCenter,
      [string]$hostHeader,
      [string]$path,
      [uint32]$attemptsBeforeDeactivation,
      [uint32]$delay,
      [uint32]$timeout,
      [string]$statusRegex,
      [string]$type,
      [string]$algorithm
   )
   $Global:catalog = Get-ServiceCatalog
   $Global:AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $loadBalancerInfoUri = ((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers")
   try {
      $loadBalancerinfo = (((Invoke-RestMethod -Uri $loadBalancerInfoUri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName})
      $loadBalancer = ($loadBalancerinfo).id
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Set-TargetResource:Failed to retrieve load balancer information `n $uri `n $($_.Exception.Message)"
   }
   $loadBalancerIdUri = ($loadBalancerInfoUri, $loadBalancer -join '/')
   $loadBalancerHealthMonitorUri = $uri = (((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers"), $loadBalancer, "healthmonitor" -join '/')
   $loadBalancerNodesUri = (((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers"),$loadBalancer, "nodes" -join '/')
   if($loadBalancer) {
      
      $nodeAddresses = Get-CloudLoadBalancers -loadBalancerName $loadBalancerName -dataCenter $dataCenter
      $servers = Get-DevicesInEnvironment -environmentGuid $nodes -dataCenter $dataCenter
      $publicIps = $servers.remoteServers.addresses.public.addr | ? {$_ -notmatch '^10\.' -and $_ -notmatch '^127\.' -and $_ -notmatch '^2001:'}
      $privateIps = $servers.localServers.addresses.private.addr
      $allNodeIps = @()
      $allNodeIps += $publicIps
      $allNodeIps += $privateIps
      $addNodeIps = @()
      $removeNodeIps = @()
      $i = 0
      foreach($allNodeIp in $allNodeIps) {
         if($nodeAddresses -notcontains $allNodeIp) {
            $addNodeIps += $allNodeIp
         }
      }
      foreach($nodeAddress in $nodeAddresses) {
         if($allNodeIps -notcontains $nodeAddress) {
            $removeNodeIps += $nodeAddress
         }
      }
      ### Add Nodes to LoadBalancer
      if($addNodeIps -ne $null) {
         $newNodes = @()
         foreach($addNode in $addNodeIps) {
            if($addNode -ne $null) {
               $newNodes += @{"address" = $addNode; "port" = $port; "condition" = "ENABLED"}
            }
         }
         $body = @{"nodes" = @($newNodes)} | ConvertTo-Json -Depth 3
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Information -EventId 1000 -Message "Adding nodes to load balancer pool `n (addNodeIps $addNodeIps) `n $body"
         $end = (Get-Date).AddMinutes(3)
         do {
             $loadBalancerinfo = (((Invoke-RestMethod -Uri $loadBalancerInfoUri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName})
             if ( $loadBalancerinfo.status -eq "ACTIVE" ) { break }
             Start-Sleep -Seconds 2
         }
         while ( (Get-Date) -le $end )
         try {
            Invoke-RestMethod -Uri $loadBalancerNodesUri -Method POST -Header $AuthToken -Body $body -ContentType application/json
         }
         catch {
            Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to add nodes to load balancer pool `n $loadBalancerNodesUri `n $body `n $($_.Exception.Message)"
         }
      }
      ### Remove Nodes from LoadBalancer
      if($removeNodeIps) {
         $ids = @()
         try {
            $serversInPool = (Invoke-RestMethod -Uri $loadBalancerNodesUri -Method Get -Headers $AuthToken -ContentType application/json)
         }
         catch {
            Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Remove Nodes:Failed to retrieve nodes in load balancer pool `n $loadBalancerNodesUri `n $($_.Exception.Message)"
         }
         foreach($ip in $removeNodeIps) {
            $ids += ($serversInPool.nodes | ? {$_.address -eq $ip}).id
         }
         foreach($id in $ids) {
            $end = (Get-Date).AddMinutes(3)
            do {
                $loadBalancerinfo = (((Invoke-RestMethod -Uri $loadBalancerInfoUri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName})
                if ( $loadBalancerinfo.status -eq "ACTIVE" ) { break }
                Start-Sleep -Seconds 2
            }
            while ( (Get-Date) -le $end )
            $uri = (((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers"), $loadBalancer, "nodes", $($id) -join '/')
            try {
               Write-EventLog -LogName DevOps -Source RS_rsCloudLoadbalancers -EntryType Information -EventId 1000 -Message "Removing Cloud Server Node $id from Cloud Load Balancer `n $uri"
               (Invoke-RestMethod -Uri $uri -Method Delete -Headers $AuthToken -ContentType application/json)
            }
            catch {
               Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Remove Nodes:Failed to remove node $id from load balancer `n $uri `n $($_.Exception.Message)"
            }
         }
      }
      ### Updating Cloud LoadBalancer configuration
      else {
         try {
            $loadBalancerMonitorInfo = (Invoke-RestMethod -Uri $loadBalancerHealthMonitorUri -Method Get -Headers $AuthToken -ContentType application/json).healthMonitor
         }
         catch {
            Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Test-TargetResource:Failed to retrieve load balancer Monitoring information `n $loadBalancerHealthMonitorUri `n $($_.Exception.Message)"
         }
         if($loadBalancerinfo.port -ne $port -or $loadBalancerinfo.protocol -ne $protocol -or $loadBalancerinfo.algorithm -ne $algorithm) {
            $body = @{ "loadBalancer" = @{ "name" = $loadBalancerName; "port" = $port; "protocol" = $protocol; "algorithm" = $algorithm;}} | ConvertTo-Json
            $uri = ($uri, $loadBalancer -join '/')
            try {
               Invoke-RestMethod -Uri $loadBalancerIdUri -Method Put -Body $body -Headers $AuthToken -ContentType application/json
            }
            catch {
               Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to update Load Balancer `n $loadBalancerIdUri `n $body `n $($_.Exception.Message)"
            }
         }
         if($type -eq "HTTP" -or $type -eq "HTTPS") {
            if($attemptsBeforeDeactivation -ne $loadBalancerMonitorInfo.attemptsBeforeDeactivation -or $delay -ne $loadBalancerMonitorInfo.delay -or $path -ne $loadBalancerMonitorInfo.patch -or $hostHeader -ne $loadBalancerMonitorInfo.hostHeader -or $statusRegex -ne $loadBalancerMonitorInfo.statusRegex -or $timeout -ne $loadBalancerMonitorInfo.timeout) {
               $body = @{"healthMonitor" = @{ "attemptsBeforeDeactivation" = $attemptsBeforeDeactivation; "delay" = $delay; "path" = $path; "hostHeader" = $hostHeader; "statusRegex" = $statusRegex; "timeout" = $timeout; "type" = $type;}} | ConvertTo-Json
            }
            else {
               $body = $null
            }
         }
         else{
            if($attemptsBeforeDeactivation -ne $loadBalancerMonitorInfo.attemptsBeforeDeactivation -or $delay -ne $loadBalancerMonitorInfo.delay -or $timeout -ne $loadBalancerMonitorInfo.timeout) {
               $body = @{"healthMonitor" = @{ "attemptsBeforeDeactivation" = $attemptsBeforeDeactivation; "delay" = $delay; "timeout" = $timeout; "type" = $type;}}| ConvertTo-Json
            }
            else {
               $body = $null
            }
         }
         if($body -ne $null) {
            do {
               try {
                  $loadBalancerinfo = (((Invoke-RestMethod -Uri $loadBalancerInfoUri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName})
                  $loadBalancer = ($loadBalancerinfo).id
                  if($loadBalancerinfo.status -eq "ACTIVE") {
                     $i = 5
                  }
                  if($i -lt 5) {
                     Start-Sleep 10
                  }
                  $i++
               }
               catch {
                  Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Test-TargetResource:Failed to retrieve load balancer information `n $($_.Exception.Message)"
               }
            }
            while($i -lt 3)
            try {
               Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Information -EventId 1000 -Message "Creating heath check for Load Balancer `n $loadBalancerHealthMonitorUri `n $body"
               Invoke-RestMethod -Uri $loadBalancerHealthMonitorUri -Method Put -Body $body -Headers $AuthToken -ContentType application/json
            }
            catch {
               Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to update health check to Load Balancer `n $loadBalancerHealthMonitorUri `n $body `n $($_.Exception.Message)"
            }
         }
      }
   }
   ### Create New Cloud LoadBalancer
   else {
      $body = @{ "loadBalancer" = @{ "name" = $loadBalancerName; "port" = $port; "protocol" = $protocol; "algorithm" = $algorithm; "virtualIps" = @( @{"type" = "PUBLIC" })}} | convertTo-Json -Depth 3
      try {
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Information -EventId 1000 -Message "Spinning up cloud load balancer $loadBalancerName `n $loadBalancerInfoUri `n $body"
         Invoke-RestMethod -Uri $loadBalancerInfoUri -Method Post -Headers $AuthToken -Body $body -ContentType application/json
      }
      catch {
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to spin up cloud load balancer $loadBalancerName `n $loadBalancerInfoUri `n $($_.Exception.Message)"
      }
      if($type -eq "HTTP" -or $type -eq "HTTPS") {
         $body = @{"healthMonitor" = @{ "attemptsBeforeDeactivation" = $attemptsBeforeDeactivation; "delay" = $delay; "path" = $path; "hostHeader" = $hostHeader; "statusRegex" = $statusRegex; "timeout" = $timeout; "type" = $type;}} | ConvertTo-Json
      }
      else{
         $body = @{"healthMonitor" = @{ "attemptsBeforeDeactivation" = $attemptsBeforeDeactivation; "delay" = $delay; "timeout" = $timeout; "type" = $type;}} | ConvertTo-Json
      }
      $end = (Get-Date).AddMinutes(3)
      do {
          $loadBalancerinfo = (((Invoke-RestMethod -Uri $loadBalancerInfoUri -Method GET -Headers $AuthToken -ContentType application/json).loadBalancers) | ? {$_.name -eq $loadBalancerName})
          if ( $loadBalancerinfo.status -eq "ACTIVE" ) { break }
          Start-Sleep -Seconds 2
      }
      while ( (Get-Date) -le $end )
      $loadBalancer = ($loadBalancerinfo).id
      $loadBalancerHealthMonitorUri = $uri = (((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudLoadBalancers").endpoints) | ? {$_.region -eq $dataCenter}).publicURL) + "/loadbalancers"), $loadBalancer, "healthmonitor" -join '/')
      try {
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Information -EventId 1000 -Message "Creating heath check for Load Balancer `n $uri `n $body"
         Invoke-RestMethod -Uri $loadBalancerHealthMonitorUri -Method Put -Body $body -Headers $AuthToken -ContentType application/json
      }
      catch {
         Write-EventLog -LogName DevOps -Source RS_rsCloudLoadBalancers -EntryType Error -EventId 1002 -Message "Failed to add health check to Load Balancer `n $uri `n $body `n $($_.Exception.Message)"
      }
   }
   
}
Export-ModuleMember -Function *-TargetResource