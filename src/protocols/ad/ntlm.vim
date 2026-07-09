# src/protocols/ad/ntlm.nim
import std/net

proc checkNTLMv1Support*(target: string, port: int = 445): string =
  # À implémenter avec un packet NTLMSSP négociation plus poussé
  "NOT_IMPLEMENTED_YET"

proc checkNTLMSigning*(target: string): string =
  # Complémentaire au check SMB
  "CHECK_VIA_SMB"
