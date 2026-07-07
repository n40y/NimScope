# src/protocols/smb.nim

import std/[net]
import winim

const smbNegotiatePacket: array[90, byte] = [
  byte 0x00, 0x00, 0x00, 0x56, 
  0xFE, 0x53, 0x4D, 0x42,       
  0x40, 0x00,                   
  0x00, 0x00,                   
  0x00, 0x00, 0x00, 0x00,       
  0x00, 0x00,                   
  0x00, 0x00,                   
  0x00, 0x00, 0x00, 0x00,       
  0x00, 0x00, 0x00, 0x00,       
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00,       
  0x00, 0x00, 0x00, 0x00,       
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x24, 0x00,                   
  0x01, 0x00,                   
  0x01, 0x00,                   
  0x00, 0x00,                   
  0x7F, 0x00, 0x00, 0x00,        
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x02, 0x02                    
]

proc checkSmbSigning*(target: string, port: int = 445): string =
  var socket = newSocket()
  try:
    socket.connect(target, Port(port), timeout = 2000)
  except:
    return "PORT_CLOSED"

  try:
    discard socket.send(addr smbNegotiatePacket[0], smbNegotiatePacket.len)
    
    var response: array[1024, byte]
    let bytesReceived = socket.recv(addr response[0], 1024)
    socket.close()

    if bytesReceived < 64:
      return "INVALID_RESPONSE"

    if bytesReceived > 72:
      let securityMode = response[72]
      if (securityMode and 0x02) == 0x02:
        return "REQUIRED"
      else:
        return "NOT_REQUIRED"
    else:
      return "PARSE_ERROR"
  except:
    socket.close()
    return "NETWORK_ERROR"

# Structure required for NetServerGetInfo
type
  SERVER_INFO_101* = object
    sv101_platform_id*: DWORD
    sv101_name*: LPWSTR
    sv101_version_major*: DWORD
    sv101_version_minor*: DWORD
    sv101_type*: DWORD
    sv101_comment*: LPWSTR

# Native function declaration from netapi32.dll
proc NetServerGetInfo*(servername: LMSTR, level: DWORD, bufptr: ptr LPBYTE): NET_API_STATUS 
  {.stdcall, dynlib: "netapi32", importc: "NetServerGetInfo".}
proc NetApiBufferFree*(Buffer: LPVOID): NET_API_STATUS 
  {.stdcall, dynlib: "netapi32", importc: "NetApiBufferFree".}

proc getRemoteOsVersion*(target: string): string =
  var buf: LPBYTE = nil
  # Convert Nim string to Wide String for the Windows API
  let wTarget = +$target 
  
  let res = NetServerGetInfo(wTarget, 101, addr buf)
  if res == 0 and buf != nil:
    let info = cast[ptr SERVER_INFO_101](buf)
    # Extract major/minor version
    let major = info.sv101_version_major
    let minor = info.sv101_version_minor
    
    result = "Windows Version " & $major & "." & $minor
    discard NetApiBufferFree(buf)
  else:
    result = "UNKNOWN (Code: " & $res & ")"
