# SDCP trust certificates

These public DER certificates let the driver validate the reader's SDCP
attestation without downloading or extracting certificates from the Windows
driver package. They are trust anchors/intermediates, not private keys.

| File | SHA-256 | Source |
| --- | --- | --- |
| `root.der` | `4c25971e3bdde59d178f7a5ef62561e9e88edd93c274ddaa522840cd4b4b517e` | Microsoft ECC Devices Root Certificate Authority 2017 |
| `hello-pca.der` | `dbfc7be1149785b5fd98a995b83184f51de39e9b277be287082f57514007c9c1` | Windows Hello Secure Devices PCA 2018 |
| `gd-ca.der` | `d06a3daedd39fc3050f30af50b4c923352cabb4f2ab81d833c999f63f5a7cbe0` | GigaDevice CA embedded in the inspected WeAct Windows package |

The driver still validates issuer dates, the certificate chain, device and
firmware signatures, and fresh session MACs. The machine-specific reader and
firmware pin is created separately after a live attestation check.
