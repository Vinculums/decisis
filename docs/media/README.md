# Media

- `social-preview.png` (1280×640): the repository's social preview. Upload it under Settings → Social preview.
- `demo.gif`: the `decisis demo` recording shown in the README.

Both are drawn by `make_media.py` from the real demo output, with Pillow and the DejaVu fonts:

```
decisis demo --out /tmp/demo-out > /tmp/demo.txt
python make_media.py docs/media /tmp/demo.txt
```
