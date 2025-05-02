import time
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Правильные импорты:
from app.crypto.utils import generate_unique_random_images
from app.crypto.chaos.dataset import generate_logistic_map_dataset
from app.crypto.core.enhanced_rsa import generate_enhanced_rsa_keys_from_image
from app.crypto.core.security import secure_decrypt


class VarianceRegularizer(layers.Layer):
    def __init__(self, lambda_reg=0.01, **kwargs):
        super().__init__(**kwargs)
        self.lambda_reg = lambda_reg

    def call(self, inputs):
        variance_loss = -self.lambda_reg * tf.reduce_mean(
            tf.math.reduce_variance(inputs, axis=0)
        )
        self.add_loss(variance_loss)
        return inputs


def chaos_activation(x):
    return tf.sin(8.0 * x) + 0.5 * tf.tanh(4.0 * x)


def build_autoencoder(image_size=(28, 28)):
    inp = keras.Input(shape=(*image_size, 1))
    x = layers.Flatten()(inp)
    x = layers.Dense(128)(x)
    x = layers.Activation(chaos_activation)(x)

    latent = layers.Dense(64, name="latent")(x)
    latent = layers.Activation(chaos_activation)(latent)
    latent = VarianceRegularizer(lambda_reg=0.01)(latent)

    x = layers.Dense(128)(latent)
    x = layers.BatchNormalization()(x)
    x = layers.Activation(chaos_activation)(x)

    decoded = layers.Dense(np.prod(image_size), activation="sigmoid")(x)
    decoded = layers.Reshape((*image_size, 1))(decoded)

    autoencoder = keras.Model(inp, decoded, name="chaos_autoencoder")
    encoder     = keras.Model(inp, latent, name="chaos_encoder")
    autoencoder.compile(optimizer="adam", loss="mse")
    return autoencoder, encoder


def dynamic_retraining_test(autoencoder, encoder, num_images=500, epochs=2, used_images=None):
    imgs = generate_unique_random_images(
        num_images, shape=(28,28,1), used_images=used_images or set()
    )
    for layer in autoencoder.layers[:-3]:
        layer.trainable = False
    autoencoder.compile(optimizer=tf.keras.optimizers.Adam(1e-4), loss="mse")

    t0 = time.time()
    autoencoder.fit(imgs, imgs, epochs=epochs, batch_size=32, verbose=1)
    train_time = time.time() - t0

    recon = autoencoder.predict(imgs, verbose=0)
    mse = float(np.mean((imgs - recon)**2))

    # Генерация RSA-ключей сразу после дообучения
    key_start = time.time()
    _priv, _pub, _, _ = generate_enhanced_rsa_keys_from_image(encoder)
    key_time = time.time() - key_start

    return train_time, mse, key_time


def dynamic_retraining_with_chaos_maps(autoencoder, encoder, num_images=500, epochs=2):
    imgs = generate_logistic_map_dataset(
        num_images=num_images,
        image_size=28,
        r=3.99,
        fixed_initial=False
    )
    for layer in autoencoder.layers[:-3]:
        layer.trainable = False
    autoencoder.compile(optimizer=tf.keras.optimizers.Adam(1e-4), loss="mse")

    t0 = time.time()
    autoencoder.fit(imgs, imgs, epochs=epochs, batch_size=32, verbose=1)
    train_time = time.time() - t0

    recon = autoencoder.predict(imgs, verbose=0)
    mse = float(np.mean((imgs - recon)**2))
    return train_time, mse
