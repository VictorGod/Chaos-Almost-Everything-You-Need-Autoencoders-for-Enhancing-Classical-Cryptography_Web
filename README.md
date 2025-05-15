# Криптографическая система на основе автоэнкодера

Данная система объединяет возможности глубинного обучения (автоэнкодер) и классической криптографии (RSA‑OAEP), создавая гибридное решение, в котором латентное представление изображений используется в качестве источника энтропии для генерации криптографических ключей. Система включает динамическое экспресс-обучение перед каждой операцией шифрования/дешифрования для повышения безопасности и адаптивности.

##  Инструкции по запуску и интеграции

- **Язык:** Python  

- **Основные библиотеки:** TensorFlow, Keras, cryptography, gmpy2, psutil  

- **Запуск:**  

  Для выполнения основного скрипта выполните:

  ```bash
  python -m venv venv
  venv\Scripts\activate
  pip install -r requirements.txt
  uvicorn app.main:app --reload
  ```

- **Документация кода:**  

[# Chaos-Almost-Everything-You-Need-Autoencoders-for-Enhancing-Classical-Cryptography](https://github.com/VictorGod/Chaos-Almost-Everything-You-Need-Autoencoders-for-Enhancing-Classical-Cryptography)
