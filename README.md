# PingSzyfr
Prosty program szyfrujący napisany w asemblerze.

## Instrukcja:
Aby zapisać jakiś tekst, z danym hasłem, trzeba wklepać takie coś:

```
echo "Super tajna wiadomosc" | ./szyfr SuperTajneHaslo > wiadomosc.bin
```
a żeby odczytać, o tak:

```
./szyfr SuperTajneHaslo < wiadomosc.bin
```
więc program jest nawet prosty w obsłudze.

Licencja GPL 3.0.
