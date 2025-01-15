### Generator kluczy prywatnych dla bitcoina

Test porównujący szybkość generowania kluczy za pomocą CPU do szybkości generowania za pomocą GPU z użyciem technologi CUDA od NVIDIA.

#### Kompilacja

`nvcc -o bitcoin-gen bitcoin-gen.cu -lcrypto -lssl`