import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np

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

import numpy as np

# Function to convert an alphabetic key to an integer matrix
def alphabetic_key_to_matrix(key, size):
    key = key.lower().replace('j', 'i')
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    key_matrix = []
    used = set()
    for char in key:
        if char not in used:
            used.add(char)
            key_matrix.append(alphabet.index(char))
    while len(key_matrix) < size * size:
        key_matrix.append(alphabet.index('x'))
    return np.array(key_matrix).reshape((size, size))

# Improved Hill Cipher function
def hill_cipher(text, key_matrix, decrypt=False):
    size = key_matrix.shape[0]

    def char_to_num(c):
        return ord(c.lower()) - ord('a')

    def num_to_char(n):
        return chr(int(round(n)) % 26 + ord('a'))

    def matrix_mod_inv(matrix, mod):
        det = int(round(np.linalg.det(matrix))) % mod
        det_inv = pow(det, -1, mod)
        matrix_adj = np.round(det_inv * np.linalg.inv(matrix)).astype(int) % mod
        return matrix_adj

    def process_text(text):
        text = text.lower().replace('j', 'i')
        while len(text) % size != 0:
            text += 'x'
        return text

    def apply_cipher(text, matrix):
        vector = [char_to_num(c) for c in text]
        result = ""
        for i in range(0, len(vector), size):
            chunk = vector[i:i + size]
            cipher_chunk = np.dot(matrix, chunk) % 26
            result += ''.join(num_to_char(num) for num in cipher_chunk)
        return result

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
                if key.replace(" ", "").isalpha():
                    size = int(np.sqrt(len(key.replace(" ", ""))))
                    key_matrix = alphabetic_key_to_matrix(key, size)
                else:
                    key_matrix = np.array([int(x) for x in key.split()]).reshape((3, 3))
                result = hill_cipher(text, key_matrix, decrypt)
            except Exception as e:
                messagebox.showerror("Error", f"Invalid key or key matrix. Error: {str(e)}")
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
# Polyalphabetic Cipher (Vigenère Cipher) with improved decryption
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
                key_matrix = np.array([int(x) for x in key.split()]).reshape((3, 3))
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

def update_subtechniques(*args):
    technique = technique_choice.get()
    if technique == "Substitution":
        subtechnique_menu['values'] = ["Vernam", "Caesar", "Playfair", "Hill", "Polyalphabetic"]
    elif technique == "Transposition":
        subtechnique_menu['values'] = ["Rail Fence", "Columnar"]
    subtechnique_choice.set(subtechnique_menu['values'][0])

# GUI setup
root = tk.Tk()
root.title("Encryption/Decryption Tool")

# Technique selection
tk.Label(root, text="Select Technique:").grid(row=0, column=0, padx=10, pady=10)
technique_choice = tk.StringVar()
technique_menu = ttk.Combobox(root, textvariable=technique_choice, state="readonly")
technique_menu['values'] = ["Substitution", "Transposition"]
technique_menu.grid(row=0, column=1, padx=10, pady=10)
technique_menu.bind("<<ComboboxSelected>>", update_subtechniques)

# Sub-technique selection
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

# Result label
result_label = tk.Label(root, text="Result:")
result_label.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Run button
run_button = tk.Button(root, text="Run", command=process_input)
run_button.grid(row=5, column=1, padx=10, pady=10)

root.mainloop()