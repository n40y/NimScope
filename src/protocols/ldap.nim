# src/protocols/ldap.nim

import std/net
import winim 

proc checkLdapPort*(target: string, port: int): bool =
  var socket = newSocket()
  try:
    socket.connect(target, Port(port), timeout = 1000)
    socket.close()
    return true
  except:
    return false

proc tryAnonymousBind*(target: string, port: int): string =
  if not checkLdapPort(target, port):
    return "PORT_CLOSED"
  
  # Initialization (winim gives us native access to wldap32 types and functions)
  let ld = ldap_init(target, int32(port))
  if ld == nil:
    return "LDAP_INIT_FAILED"
  
  let rc = ldap_simple_bind_s(ld, nil, nil)
  discard ldap_unbind(ld)
  
  if rc == 0:
    return "SUCCESS"
  else:
    return "BIND_DENIED (Code: " & $rc & ")"
