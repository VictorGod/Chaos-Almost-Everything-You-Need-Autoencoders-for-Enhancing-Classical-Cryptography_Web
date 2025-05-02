import numpy as np

def logistic_map(x, r=3.99):
    return r * x * (1 - x)

def generate_logistic_map_image(image_size=28, initial_value=0.4, r=3.99):
    seq = []
    x = initial_value
    for _ in range(image_size*image_size):
        x = logistic_map(x, r)
        seq.append(x)
    img = np.array(seq).reshape((image_size,image_size))
    return img

def generate_logistic_map_dataset(num_images, image_size=28, r=3.99, fixed_initial=True):
    data = []
    for _ in range(num_images):
        init = 0.4 if fixed_initial else np.random.rand()
        img = generate_logistic_map_image(image_size, init, r)
        data.append(img)
    return np.array(data)[...,np.newaxis]
