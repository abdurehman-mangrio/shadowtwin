import qrcode

class QrGenerator:
    def __init__(self, url, output_file="portal_qr.png"):
        self.url = url
        self.output_file = output_file

    def generate(self):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.url)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        img.save(self.output_file)
        print(f"[+] QR Code generated: {self.output_file}")
        print(f"[+] Link embedded: {self.url}")