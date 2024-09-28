import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES Encryption
def aes_encrypt(text, key, rounds):
    key = pad(key.encode(), AES.block_size)[:16]  # AES key must be 16, 24, or 32 bytes
    cipher = AES.new(key, AES.MODE_CBC)  # Using CBC mode
    iv = cipher.iv  # Initialization vector
    encrypted_text = cipher.encrypt(pad(text.encode(), AES.block_size))
    return (iv + encrypted_text).hex()  # Return hex string

# AES Decryption
def aes_decrypt(encrypted_text, key, rounds):
    encrypted_text = bytes.fromhex(encrypted_text)  # Convert hex string back to bytes
    key = pad(key.encode(), AES.block_size)[:16]
    iv = encrypted_text[:AES.block_size]  # Extract the IV from the start
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text[AES.block_size:]), AES.block_size)
    return decrypted_text.decode()

# DES Encryption
def des_encrypt(text, key, rounds):
    key = pad(key.encode(), DES.block_size)[:8]  # DES key must be 8 bytes
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv
    encrypted_text = cipher.encrypt(pad(text.encode(), DES.block_size))
    return (iv + encrypted_text).hex()  # Convert to hex and return

# DES Decryption
def des_decrypt(encrypted_text, key, rounds):
    encrypted_text = bytes.fromhex(encrypted_text)  # Convert hex string back to bytes
    key = pad(key.encode(), DES.block_size)[:8]
    iv = encrypted_text[:DES.block_size]  # Extract the IV from the start
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text[DES.block_size:]), DES.block_size)
    return decrypted_text.decode()

def mod_inverse(a, m):
    """Calculate modular inverse of a with respect to m using Extended Euclidean Algorithm"""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

# Vernam Cipher
def vernam_cipher(text, key, decrypt=False):
    if len(text) != len(key):
        return "Error: Key must be the same length as the text."
    result = ""
    for i in range(len(text)):
        text_char = text[i]
        key_char = key[i]
        if text_char.isalpha():
            text_char = text_char.upper()
            key_char = key_char.upper()
            text_num = ord(text_char) - ord('A')
            key_num = ord(key_char) - ord('A')
            if decrypt:
                decrypted_num = (text_num ^ key_num) % 26
                cipher_char = chr(decrypted_num + ord('A'))
            else:
                encrypted_num = (text_num ^ key_num) % 26
                cipher_char = chr(encrypted_num + ord('A'))
            result += cipher_char if text_char.isupper() else cipher_char.lower()
        else:
            result += text_char
    return result
def matrix_mod_inverse(matrix, mod):
    """Calculate the inverse of a matrix modulo mod"""
    det = int(np.round(np.linalg.det(matrix)))  # Determinant of the matrix
    det_inv = mod_inverse(det, mod)  # Modular inverse of the determinant

    if det_inv is None:
        raise ValueError("The matrix is not invertible")

    # Matrix of minors, then transpose it (cofactor matrix)
    matrix_minor = np.linalg.inv(matrix).T * det
    matrix_adj = matrix_minor % mod  # Adjugate matrix

    return (det_inv * matrix_adj) % mod

# Playfair Cipher
def playfair_cipher(text, key, decrypt=False):
    def generate_key_matrix(key):
        key = key.lower().replace("j", "i")
        alphabet = "abcdefghiklmnopqrstuvwxyz"
        key_matrix = []
        used = set()
        for char in key:
            if char not in used:
                used.add(char)
                key_matrix.append(char)
        for char in alphabet:
            if char not in used:
                key_matrix.append(char)
        return [key_matrix[i:i + 5] for i in range(0, 25, 5)]

    def find_position(matrix, char):
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return row, col
        return None, None

    def prepare_text(text):
        text = text.lower().replace("j", "i")
        new_text = ""
        i = 0
        while i < len(text):
            new_text += text[i]
            if i + 1 < len(text) and text[i] == text[i + 1]:
                new_text += 'x'
            elif i + 1 < len(text):
                new_text += text[i + 1]
                i += 1
            else:
                new_text += 'x'
            i += 1
        return new_text

    def playfair_pair(matrix, char1, char2, decrypt):
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)
        if row1 == row2:
            if decrypt:
                return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            else:
                return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            if decrypt:
                return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            else:
                return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            return matrix[row1][col2] + matrix[row2][col1]

    text = prepare_text(text)
    key_matrix = generate_key_matrix(key)
    result = ""
    for i in range(0, len(text), 2):
        result += playfair_pair(key_matrix, text[i], text[i + 1], decrypt)
    return result

# Function to convert an alphabetic key to an integer matrix
def alphabetic_key_to_matrix(key, size):
    key = key.lower().replace('j', 'i')  # Convert to lowercase and handle 'j' -> 'i'
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key_matrix = []
    
    for char in key:
        if char in alphabet:
            key_matrix.append(alphabet.index(char))
    
    # Pad the key matrix if necessary to fit the matrix size (size x size)
    while len(key_matrix) < size * size:
        key_matrix.append(alphabet.index('x'))  # Padding with 'x' (which is 23)
    
    return np.array(key_matrix).reshape((size, size))
def decrypt(ciphertext, key_matrix):
    """Decrypts the ciphertext using the given key matrix in Hill Cipher"""
    n = len(key_matrix)  # Size of key matrix (n x n)
    ciphertext = ciphertext.upper().replace(" ", "")
    ciphertext_vector = [ord(char) - ord('A') for char in ciphertext]

    # Pad ciphertext vector if necessary
    while len(ciphertext_vector) % n != 0:
        ciphertext_vector.append(0)

    ciphertext_vector = np.array(ciphertext_vector).reshape(-1, n).T

    # Compute the inverse key matrix modulo 26
    key_matrix_inv = matrix_mod_inverse(key_matrix, 26)

    # Decrypt the ciphertext by multiplying the inverse key matrix with ciphertext vector
    decrypted_vector = np.dot(key_matrix_inv, ciphertext_vector) % 26
    decrypted_vector = decrypted_vector.T.flatten()

    decrypted_text = ''.join(chr(int(num) + ord('A')) for num in decrypted_vector)
    return decrypted_text

# Improved Hill Cipher function
def hill_cipher(text, key_matrix, decrypt=False):
    size = key_matrix.shape[0]

    def char_to_num(c):
        return ord(c.lower()) - ord('a')

    def num_to_char(n):
        return chr(int(round(n)) % 26 + ord('a'))

    # Calculate the modular inverse of the matrix
    def matrix_mod_inv(matrix, mod):
        det = int(round(np.linalg.det(matrix))) % mod
        det_inv = pow(det, -1, mod)
        matrix_adj = np.round(det_inv * np.linalg.inv(matrix)).astype(int) % mod
        return matrix_adj

    # Prepare text by removing non-alphabetic characters and padding with 'x'
    def process_text(text):
        text = text.lower().replace('j', 'i')
        processed_text = ''.join([c for c in text if c.isalpha()])
        while len(processed_text) % size != 0:
            processed_text += 'x'
        return processed_text

    # Apply the Hill Cipher matrix to the text
    def apply_cipher(text, matrix):
        vector = [char_to_num(c) for c in text]
        result = ""
        for i in range(0, len(vector), size):
            chunk = vector[i:i + size]
            cipher_chunk = np.dot(matrix, chunk) % 26
            result += ''.join(num_to_char(num) for num in cipher_chunk)
        return result
    
    # Process the text and perform encryption or decryption
    text = process_text(text)
    if decrypt:
        key_matrix = matrix_mod_inv(key_matrix, 26)
    return apply_cipher(text, key_matrix)

# Function to process input from the GUI (updated for Hill Cipher)
def process_input():
    text = text_input.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    technique = technique_choice.get()
    sub_technique = subtechnique_choice.get()
    action = action_choice.get()

    if action == "Encryption":
        decrypt = False
    else:
        decrypt = True

    if technique == "Substitution":
        if sub_technique == "Vernam":
            result = vernam_cipher(text, key, decrypt)
        elif sub_technique == "Playfair":
            result = playfair_cipher(text, key, decrypt)
        elif sub_technique == "Hill":
            try:
                size = int(np.sqrt(len(key)))  # Determine size of the matrix (e.g., 3x3)
                key_matrix = alphabetic_key_to_matrix(key, size)
                result = hill_cipher(text, key_matrix, decrypt)
            except:
                messagebox.showerror("Error", "Invalid key matrix.")
                return
        elif sub_technique == "Caesar":
            try:
                shift = int(key)
                result = caesar_cipher(text, shift, decrypt)
            except ValueError:
                messagebox.showerror("Error", "Invalid shift value.")
                return
        elif sub_technique == "Polyalphabetic":
            result = polyalphabetic_cipher(text, key, decrypt)
        elif sub_technique == "AES":
            if decrypt:
                result = aes_decrypt(bytes.fromhex(text), key)
            else:
                result = aes_encrypt(text, key).hex()
        elif sub_technique == "DES":
            if decrypt:
                result = des_decrypt(bytes.fromhex(text), key)
            else:
                result = des_encrypt(text, key).hex()
    elif technique == "Transposition":
        if sub_technique == "Rail Fence":
            try:
                key = int(key)
                result = rail_fence_cipher(text, key, decrypt)
            except ValueError:
                messagebox.showerror("Error", "Invalid key value.")
                return
        elif sub_technique == "Columnar":
            result = columnar_transposition_cipher(text, key, decrypt)
    
    result_label.config(text=f"Result: {result}")


# Caesar Cipher
def caesar_cipher(text, shift, decrypt=False):
    shift = -shift if decrypt else shift
    result = ""
    for char in text:
        if char.isalpha():
            shifted = chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 + shift) % 26 + 97)
            result += shifted
        else:
            result += char
    return result

# Rail Fence Cipher
def rail_fence_cipher(text, key, decrypt=False):
    if decrypt:
        rail = [['\n' for _ in range(len(text))] for _ in range(key)]
        dir_down = None
        row, col = 0, 0
        for i in range(len(text)):
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False
            rail[row][col] = '*'
            col += 1
            row += 1 if dir_down else -1

        index = 0
        for i in range(key):
            for j in range(len(text)):
                if rail[i][j] == '*' and index < len(text):
                    rail[i][j] = text[index]
                    index += 1

        result = []
        row, col = 0, 0
        for i in range(len(text)):
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False
            if rail[row][col] != '*':
                result.append(rail[row][col])
                col += 1
            row += 1 if dir_down else -1
        return ''.join(result)
    else:
        rail = [['\n' for _ in range(len(text))] for _ in range(key)]
        dir_down = None
        row, col = 0, 0
        for char in text:
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False
            rail[row][col] = char
            col += 1
            row += 1 if dir_down else -1

        result = []
        for i in range(key):
            for j in range(len(text)):
                if rail[i][j] != '\n':
                    result.append(rail[i][j])
        return ''.join(result)

# Columnar Transposition Cipher
def columnar_transposition_cipher(text, key, decrypt=False):
    n = len(key)
    sorted_key = sorted([(k, i) for i, k in enumerate(key)])
    
    if decrypt:
        num_rows = len(text) // n
        extra_chars = len(text) % n
        cols = ['' for _ in range(n)]
        col_lengths = [(num_rows + 1) if i < extra_chars else num_rows for i in range(n)]
        index = 0
        for i, (_, col_index) in enumerate(sorted_key):
            cols[col_index] = text[index: index + col_lengths[i]]
            index += col_lengths[i]
        result = []
        for row in range(num_rows + (1 if extra_chars > 0 else 0)):
            for col in cols:
                if row < len(col):
                    result.append(col[row])
        return ''.join(result)
    else:
        columns = ['' for _ in range(n)]
        for i, char in enumerate(text):
            columns[i % n] += char
        result = []
        for _, col_index in sorted_key:
            result.append(columns[col_index])
        return ''.join(result)

# Polyalphabetic Cipher (Vigenère Cipher)
def polyalphabetic_cipher(text, key, decrypt=False):
    def repeat_key(text, key):
        key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
        return key

    def char_to_num(c):
        return ord(c.lower()) - ord('a')

    def num_to_char(n):
        return chr(n % 26 + ord('a'))

    def shift_char(c, shift, decrypt=False):
        if c.isalpha():
            shift = -shift if decrypt else shift
            base = ord('A') if c.isupper() else ord('a')
            return chr((ord(c) - base + shift) % 26 + base)
        else:
            return c

    key = repeat_key(text, key)
    result = ""

    for t, k in zip(text, key):
        shift = char_to_num(k.upper())
        result += shift_char(t, shift, decrypt)

    return result


# Function to process input from the GUI

def process_input():
    text = text_input.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    technique = technique_choice.get()
    sub_technique = subtechnique_choice.get()
    action = action_choice.get()
    rounds = int(round_input.get()) if round_input.get().isdigit() else None

    if action == "Encryption":
        decrypt = False
    else:
        decrypt = True

    try:
        if technique == "Substitution":
            if sub_technique == "Vernam":
                result = vernam_cipher(text, key, decrypt)
            elif sub_technique == "Playfair":
                result = playfair_cipher(text, key, decrypt)
            elif sub_technique == "Hill":
                try:
                    size = int(np.sqrt(len(key)))
                    key_matrix = alphabetic_key_to_matrix(key, size)
                    result = hill_cipher(text, key_matrix, decrypt)
                except Exception as e:
                    messagebox.showerror("Error", f"Invalid key matrix: {str(e)}")
                    return
            elif sub_technique == "Caesar":
                try:
                    shift = int(key)
                    result = caesar_cipher(text, shift, decrypt)
                except ValueError:
                    messagebox.showerror("Error", "Invalid shift value.")
                    return
            elif sub_technique == "Polyalphabetic":
                result = polyalphabetic_cipher(text, key, decrypt)

        elif technique == "AES":
            if decrypt:
                result = aes_decrypt(text, key, rounds)
            else:
                result = aes_encrypt(text, key, rounds)

        elif technique == "DES":
            if decrypt:
                result = des_decrypt(text, key, rounds)
            else:
                result = des_encrypt(text, key, rounds)
        elif technique == "Transposition":
            if sub_technique == "Rail Fence":
                try:
                    key = int(key)
                    result = rail_fence_cipher(text, key, decrypt)
                except ValueError:
                    messagebox.showerror("Error", "Invalid key value.")
                    return
            elif sub_technique == "Columnar":
                result = columnar_transposition_cipher(text, key, decrypt)
            
        result_label.config(text=f"Result: {result}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Function to update sub-techniques
def update_subtechniques(*args):
    technique = technique_choice.get()
    if technique == "Substitution":
        subtechnique_menu['values'] = ["Vernam", "Caesar", "Playfair", "Hill", "Polyalphabetic"]
    elif technique == "Transposition":
        subtechnique_menu['values'] = ["Rail Fence", "Columnar"]
        subtechnique_choice.set(subtechnique_menu['values'][0])
        subtechnique_menu.grid(row=1, column=1, padx=10, pady=10)
        round_label.grid_remove()
        round_input.grid_remove()
    elif technique == "AES" or technique == "DES":
        subtechnique_menu.grid_remove()  # No sub-techniques for AES/DES
        round_label.grid(row=5, column=0, padx=10, pady=10)
        round_input.grid(row=5, column=1, padx=10, pady=10)
    else:
        subtechnique_menu.grid_remove()
        round_label.grid_remove()
        round_input.grid_remove()


#GUI Setup
root = tk.Tk()
root.title("CipherVault")

# Technique selection
tk.Label(root, text="Select Technique:").grid(row=0, column=0, padx=10, pady=10)
technique_choice = tk.StringVar()
technique_menu = ttk.Combobox(root, textvariable=technique_choice, state="readonly")
technique_menu['values'] = ["Substitution", "AES", "DES", "Transposition"]
technique_menu.grid(row=0, column=1, padx=10, pady=10)
technique_menu.bind("<<ComboboxSelected>>", update_subtechniques)

# Sub-technique selection (appears only for Substitution)
tk.Label(root, text="Select Sub-Technique:").grid(row=1, column=0, padx=10, pady=10)
subtechnique_choice = tk.StringVar()
subtechnique_menu = ttk.Combobox(root, textvariable=subtechnique_choice, state="readonly")
subtechnique_menu.grid(row=1, column=1, padx=10, pady=10)

# Operation selection
tk.Label(root, text="Select Operation:").grid(row=2, column=0, padx=10, pady=10)
action_choice = tk.StringVar()
action_menu = ttk.Combobox(root, textvariable=action_choice, state="readonly")
action_menu['values'] = ["Encryption", "Decryption"]
action_menu.grid(row=2, column=1, padx=10, pady=10)

# Text input
tk.Label(root, text="Enter Text:").grid(row=3, column=0, padx=10, pady=10)
text_input = tk.Text(root, height=5, width=40)
text_input.grid(row=3, column=1, padx=10, pady=10)

# Key input
tk.Label(root, text="Enter Key:").grid(row=4, column=0, padx=10, pady=10)
key_input = tk.Entry(root)
key_input.grid(row=4, column=1, padx=10, pady=10)

# Rounds input (for AES and DES only)
round_label = tk.Label(root, text="Enter Number of Rounds:")
round_input = tk.Entry(root)

# Result label
result_label = tk.Label(root, text="Result:")
result_label.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

# Run button
run_button = tk.Button(root, text="Run", command=process_input)
run_button.grid(row=6, column=1, padx=10, pady=10)

footer_label = ttk.Label(root, text="© 2024 CipherVault By ISHA. All rights reserved.", anchor="center")
footer_label.grid(row=8, column=0, columnspan=2, pady=10)

root.mainloop()
