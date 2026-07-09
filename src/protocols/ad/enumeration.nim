# src/protocols/ad/enumeration.nim
import winim
import ldap

proc enumerateUsers*(target: string, port: int = 389): seq[string] =
    result = @[]
    let ld = ldap_init(target, int32(port))
    if ld == nil: return

    # Query exemple : (&(objectClass=user)(objectCategory=person))
    discard ldap_unbind(ld)
    echo "[+] User enumeration framework ready"
