from PIL import Image
import hashlib

def hide_text_in_image(input_image_path, output_image_path, secret_message, key, color_channel='b'):
    image = Image.open(input_image_path)
    binary_secret_message = ''.join(format(ord(char), '08b') for char in secret_message)

    if len(binary_secret_message) > image.width * image.height * 3:
        raise ValueError("Message too large to hide in image")

    index = 0
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = image.getpixel((i, j))
            if index < len(binary_secret_message):
                if color_channel == 'r':
                    image.putpixel((i, j), (int(format(r, '08b')[:-1] + binary_secret_message[index], 2), g, b))
                elif color_channel == 'g':
                    image.putpixel((i, j), (r, int(format(g, '08b')[:-1] + binary_secret_message[index], 2), b))
                elif color_channel == 'b':
                    image.putpixel((i, j), (r, g, int(format(b, '08b')[:-1] + binary_secret_message[index], 2)))
                index += 1

    image.save(output_image_path)

def extract_text_from_image(input_image_path, key, color_channel='b'):
    image = Image.open(input_image_path)
    binary_secret_message = ""
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = image.getpixel((i, j))
            if color_channel == 'r':
                binary_secret_message += format(r, '08b')[-1]
            elif color_channel == 'g':
                binary_secret_message += format(g, '08b')[-1]
            elif color_channel == 'b':
                binary_secret_message += format(b, '08b')[-1]

    secret_message = "".join(chr(int(binary_secret_message[i:i + 8], 2)) for i in range(0, len(binary_secret_message), 8))
    return secret_message

def hash_password(password):
    # Using SHA-256 for password hashing
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    input_image_path = input("Enter the input image path: ")
    output_image_path = input("Enter the output image path: ")
    secret_message = input("Enter the message to hide: ")
    password = input("Enter the password: ")
    color_channel = input("Enter the color channel (r/g/b): ")

    hashed_password = hash_password(password)

    hide_text_in_image(input_image_path, output_image_path, secret_message, hashed_password, color_channel)

    input_image_path = input("Enter the input image path to extract message from: ")
    entered_password = input("Enter the password to decrypt the message: ")
    entered_password_hashed = hash_password(entered_password)

    if hashed_password == entered_password_hashed:
        decrypted_message = extract_text_from_image(input_image_path, entered_password_hashed, color_channel)
        print("Decrypted message: ", decrypted_message)
    else:
        print("Password incorrect !!!!")
        print("Thanks for executing")

if __name__ == "__main__":
    main()
