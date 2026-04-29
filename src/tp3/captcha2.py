import requests
from PIL import Image
import pytesseract
from io import BytesIO
import re
import hashlib

BASE_URL = "http://31.220.95.27:9002/captcha2/"
CAPTCHA_URL = "http://31.220.95.27:9002/captcha.php"

def lire_captcha(session):
    img_response = session.get(CAPTCHA_URL)
    image = Image.open(BytesIO(img_response.content))
    image = image.convert("L")
    image = image.point(lambda x: 255 if x > 128 else 0)
    return pytesseract.image_to_string(image, config="--psm 7 -c tessedit_char_whitelist=0123456789").strip()

session = requests.Session()
session.get(BASE_URL)

# Étape 1 : premier POST pour récupérer le hash indice
texte = lire_captcha(session)
payload = {"flag": 2000, "captcha": texte, "submit": "Submit"}
result = session.post(BASE_URL, data=payload)
hex_values = re.findall(r'\b[0-9a-f]{6}\b', result.text)

if not hex_values:
    print("❌ Pas de hash trouvé, CAPTCHA invalide, relance le script")
    exit()

hash_indice = hex_values[0]
print(f"Hash indice reçu : {hash_indice}")

# Étape 2 : trouver quel flag correspond à ce hash
flag_trouve = None
for flag in range(2000, 3001):
    if hashlib.md5(str(flag).encode()).hexdigest().startswith(hash_indice):
        flag_trouve = flag
        print(f"✅ Flag identifié : {flag}")
        break

if not flag_trouve:
    print("❌ Aucun flag ne correspond, le hash n'est peut-être pas MD5")
    exit()

# Étape 3 : soumettre le bon flag avec un nouveau captcha
session2 = requests.Session()
session2.get(BASE_URL)
texte2 = lire_captcha(session2)
payload2 = {"flag": flag_trouve, "captcha": texte2, "submit": "Submit"}
result2 = session2.po
