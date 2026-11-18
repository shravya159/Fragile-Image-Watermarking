import io
import hashlib

import numpy as np
import streamlit as st
from PIL import Image

BLOCK_SIZE = 8

st.set_page_config(
    page_title="Fragile Image Watermarking",
    page_icon="🔍",
    layout="wide"
)


# Convert image into NumPy array
def image_to_array(image):
    return np.array(image.convert("RGB"), dtype=np.uint8)


# Generate authentication tag
def embed_watermark(image):

    array = image_to_array(image).copy()
    height, width, _ = array.shape

    rows = height // BLOCK_SIZE
    cols = width // BLOCK_SIZE

    if rows == 0 or cols == 0:
        raise ValueError("Image must be at least 8x8 pixels.")

    for row in range(rows):
        for col in range(cols):

            y = row * BLOCK_SIZE
            x = col * BLOCK_SIZE

            block = array[
                y:y + BLOCK_SIZE,
                x:x + BLOCK_SIZE
            ].copy()

            # Clear 16 carrier bits
            for i in range(16):
                r, c = divmod(i, 8)
                block[r, c, 0] &= 254

            digest = hashlib.sha256(block.tobytes()).digest()
            tag = int.from_bytes(digest[:2], "big")

            # Embed 16-bit authentication tag
            for i in range(16):

                r, c = divmod(i, 8)
                bit = (tag >> (15 - i)) & 1

                array[y + r, x + c, 0] = (
                    (int(array[y + r, x + c, 0]) & 254) | bit
                )

    return Image.fromarray(array)


# Verify watermark
def verify_watermark(image):

    array = image_to_array(image)
    height, width, _ = array.shape

    rows = height // BLOCK_SIZE
    cols = width // BLOCK_SIZE

    tamper_map = np.zeros((height, width), dtype=np.uint8)

    suspicious_blocks = 0
    total_blocks = rows * cols

    for row in range(rows):
        for col in range(cols):

            y = row * BLOCK_SIZE
            x = col * BLOCK_SIZE

            block = array[
                y:y + BLOCK_SIZE,
                x:x + BLOCK_SIZE
            ].copy()

            # Read stored tag
            stored_tag = 0

            for i in range(16):

                r, c = divmod(i, 8)

                bit = int(array[y + r, x + c, 0]) & 1

                stored_tag = (stored_tag << 1) | bit

            # Clear embedded bits
            for i in range(16):

                r, c = divmod(i, 8)

                block[r, c, 0] &= 254

            # Recalculate tag
            digest = hashlib.sha256(block.tobytes()).digest()
            expected_tag = int.from_bytes(digest[:2], "big")

            if stored_tag != expected_tag:

                suspicious_blocks += 1

                tamper_map[
                    y:y + BLOCK_SIZE,
                    x:x + BLOCK_SIZE
                ] = 255

    return tamper_map, suspicious_blocks, total_blocks


# Create red overlay for suspicious regions
def create_overlay(image, tamper_map):

    array = image_to_array(image)
    result = array.copy()

    mask = tamper_map == 255

    red = np.array([255, 0, 0], dtype=np.float32)

    result[mask] = (
        0.5 * result[mask].astype(np.float32)
        + 0.5 * red
    ).astype(np.uint8)

    return Image.fromarray(result)


# Application title
st.title("Fragile Image Watermarking for Tamper Detection")

st.write("Digital Image Processing Project")

st.warning(
    "Educational prototype. Use PNG images and avoid resizing "
    "or recompressing images during testing."
)


# STEP 1: Upload Original Image
st.header("Step 1: Upload Original Image")

original_file = st.file_uploader(
    "Choose an original image",
    type=["png", "jpg", "jpeg"],
    key="original"
)


if original_file is not None:

    original_image = Image.open(original_file).convert("RGB")

    st.image(
        original_image,
        caption="Original Image",
        width=400
    )

    # STEP 2: Generate Watermark
    st.header("Step 2: Generate Watermark")

    if st.button("Generate Watermark"):

        try:

            watermarked_image = embed_watermark(original_image)

            buffer = io.BytesIO()

            watermarked_image.save(buffer, format="PNG")

            watermarked_bytes = buffer.getvalue()

            st.session_state["watermarked_bytes"] = watermarked_bytes

            st.success("Watermark generated successfully!")

            st.image(
                watermarked_image,
                caption="Watermarked Image",
                width=400
            )

            st.download_button(
                "Download Watermarked Image",
                data=watermarked_bytes,
                file_name="watermarked_image.png",
                mime="image/png"
            )

        except ValueError as error:

            st.error(str(error))


# STEP 3: Verify Image
st.header("Step 3: Upload Image for Verification")

test_file = st.file_uploader(
    "Choose the watermarked image or modified image",
    type=["png", "jpg", "jpeg"],
    key="verification"
)


if test_file is not None:

    test_image = Image.open(test_file).convert("RGB")

    st.image(
        test_image,
        caption="Image for Verification",
        width=400
    )

    if st.button("Detect Tampering"):

        if test_image.width < BLOCK_SIZE or test_image.height < BLOCK_SIZE:

            st.error("Image must be at least 8x8 pixels.")

        else:

            tamper_map, suspicious, total = verify_watermark(test_image)

            st.subheader("Detection Results")

            st.write(f"Total Blocks: {total}")

            st.write(f"Suspicious Blocks: {suspicious}")

            st.write(f"Unaffected Blocks: {total - suspicious}")

            if suspicious == 0:

                st.success("No suspicious blocks detected.")

            else:

                st.error("Possible tampering detected!")

            st.image(
                create_overlay(test_image, tamper_map),
                caption="Tampering Detection Result",
                width=400
            )

            st.image(
                tamper_map,
                caption="Tamper Map",
                width=400
            )