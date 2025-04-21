from Crypto.Cipher import AES                   #|
from Crypto.Random import get_random_bytes      #|bu üçü AES şifreleme ve çözme işlemleri için kullanılır
from Crypto.Util.Padding import pad, unpad      #|
from math import gcd            #Hill Cipher anahtarının uygun olup olmadığını kontrol etmek için determinant hesaplamalarında kullanılabilir.
import numpy as np              #Hill Cipher matris işlemleri için kullanılır.

#Hill Cipher, matris çarpımına dayalı bir polialfabetik yerine koyma şifreleme yöntemidir.

# Hill Cipher Anahtar Matrisi (Geçerli olmalı: determinantı mod 26 içinde terslenebilir - Matrisin modüler tersi alınabilir olmalıdır.)
# Farklı anahtarlar farklı şifrelemeler üretir, yani güvenliği belirleyen temel unsurdur.)
# (plaintext) sayısal değerlere çevirerek bu matris ile çarpar ve mod 26 alarak şifreli metni oluşturur.

def mod_inverse_matrix(matrix, mod=26):        # Bu fonksiyon, Hill Cipher'da şifre çözmek için gerekli olan anahtar matrisin(HILL_KEY) tersini bulur.
    """Modüler ters matris hesaplama"""
    det = int(round(np.linalg.det(matrix)))  # Matrisin determinantını hesapla
    det_inv = pow(det, -1, mod)  # Determinantın modüler tersini al
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % mod          # Adjugate (Eşlenik) matris
    return (det_inv * adjugate) % mod  # Modüler ters matris

def hill_encrypt(text, key_matrix):
    """Hill Cipher ile şifreleme"""
    text = text.upper().replace(" ", "")         # Metni büyük harfe çevir ve boşlukları kaldır
    if len(text) % 2 == 1:      #Harf sayısı tek ise
        text += "X"  # Harf sayısını çift yapmak için X ekle

    text_numbers = [ord(char) - ord('A') for char in text]           # Harfleri sayıya çevir (A=0, B=1, ... Z=25)
    text_matrix = np.array(text_numbers).reshape(-1, 2).T            # 2'li gruplar halinde matrise çevir
    
    encrypted_matrix = np.dot(key_matrix, text_matrix) % 26          # Anahtar matrisiyle çarp ve mod 26 al (Hill Cipher işlemi)-(İngiliz alfabesi 26 harf içerdiği için)
    encrypted_text = ''.join(chr(num + ord('A')) for num in encrypted_matrix.T.flatten())       # Şifreli harfleri tekrar ASCII'ye çevir

    return encrypted_text       #şifreli metni döndürür.

def hill_decrypt(encrypted_text, key_matrix):           #Bu fonksiyon, şifreli metni modüler ters matris yardımıyla çözer.
    """Hill Cipher ile şifre çözme"""
    inverse_key = mod_inverse_matrix(key_matrix)  # Anahtar matrisin modüler tersini al
    encrypted_numbers = [ord(char) - ord('A') for char in encrypted_text]         # Şifrelenmiş harfleri sayıya çevir
    encrypted_matrix = np.array(encrypted_numbers).reshape(-1, 2).T              # 2'li gruplara ayır

    decrypted_matrix = np.dot(inverse_key, encrypted_matrix) % 26                # Şifre çözme işlemi
    decrypted_text = ''.join(chr(num + ord('A')) for num in decrypted_matrix.T.flatten())            # Sayıları tekrar harfe çevir

    return decrypted_text

#AES, 128-bit anahtarla çalışan simetrik bir blok şifreleme algoritmasıdır. Burada ECB (Electronic Codebook) modu kullanılmıştır.

# AES Şifreleme
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_ECB)   # AES nesnesini oluştur (ECB Modu)
    padded_text = pad(plain_text.encode(), AES.block_size) # Metni 16 byte'a tamamla (padding)
    encrypted_text = cipher.encrypt(padded_text)            # AES ile şifrele
    return encrypted_text

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key, AES.MODE_ECB)   # AES çözme nesnesi oluştur
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size).decode()  # Padding'i kaldır ve metni al
    return decrypted_text           #Bu fonksiyon, AES şifrelenmiş veriyi çözüp orijinal metni döndürür.


# Ana Program => Bu sistem, AES ile şifreleyip, ardından Hill Cipher ile tekrar şifreleyerek güvenliği artırır.
def hybrid_encrypt(plain_text, aes_key, hill_key):
    # AES ile şifrele
    aes_encrypted = aes_encrypt(plain_text, aes_key)         # AES ile şifrele
    
    # AES şifresi ile Hill Cipher ile şifrele
    aes_encrypted_numbers = [byte for byte in aes_encrypted]  # AES şifreli byte'ları sayılara çevir
    aes_encrypted_text = ''.join(chr(num) for num in aes_encrypted_numbers)  # ASCII'ye çevir
    hill_encrypted = hill_encrypt(aes_encrypted_text, hill_key)         # Hill Cipher ile şifrele

    return hill_encrypted, aes_encrypted  # Hill ve AES şifreli verileri döndür

#Önce Hill Cipher çözülür.Ardından AES çözülerek orijinal metne ulaşılır.
def hybrid_decrypt(hill_encrypted, aes_encrypted, aes_key, hill_key):
    # Hill Cipher ile çözme
    hill_decrypted = hill_decrypt(hill_encrypted, hill_key)
    
    # Hill çözülmüş verisi ile AES ile çözme
    aes_decrypted = aes_decrypt(aes_encrypted, aes_key)

    return aes_decrypted  # Son çözülmüş metin

# Anahtarlar
aes_key = get_random_bytes(16)  # AES için 16 byte'lık -128 bit- rastgele anahtar oluştur
hill_key = np.array([[3, 3], [2, 5]])  # Hill Cipher anahtarı

# Orijinal metni kullanıcıdan al
plain_text = input("Lütfen şifrelenecek metni girin: ").upper()  # Kullanıcıdan metin al ve büyük harfe çevir

# Şifreleme
hill_encrypted, aes_encrypted = hybrid_encrypt(plain_text, aes_key, hill_key)       

print(f"Orijinal Mesaj: {plain_text}")
print(f"AES ile Şifrelenmiş Mesaj: {aes_encrypted}")
print(f"Hill Cipher ile Şifrelenmiş Mesaj: {hill_encrypted}")

# Şifre çözme
decrypted_message = hybrid_decrypt(hill_encrypted, aes_encrypted, aes_key, hill_key)
print(f"Çözülen Mesaj: {decrypted_message}")
#sbox