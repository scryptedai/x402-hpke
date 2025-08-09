from typing import Dict


def build_x402_headers(x: Dict) -> Dict[str, str]:
    return {
        "X-X402-Invoice-Id": str(x["invoiceId"]),
        "X-X402-Chain-Id": str(int(x["chainId"])),
        "X-X402-Token-Contract": str(x["tokenContract"]),
        "X-X402-Amount": str(x["amount"]),
        "X-X402-Recipient": str(x["recipient"]),
        "X-X402-Tx-Hash": str(x["txHash"]),
        "X-X402-Expiry": str(int(x["expiry"])),
        "X-X402-Price-Hash": str(x["priceHash"]),
    }