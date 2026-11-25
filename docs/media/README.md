# Media

- `logo.png` (1024×1024): the decisis logo, the mark and the wordmark on dark navy. The README opens with it.
- `logo-mark.png`: the mark alone on a transparent background, cut from `logo.png`.
- `social-preview.png` (1280×640): the repository's social preview, with the mark next to the name. Upload it under Settings → Social preview.
- `demo.gif`: the `decisis demo` recording shown in the README.

`social-preview.png` and `demo.gif` are drawn by `make_media.py` from the real demo output and `logo-mark.png`, with Pillow and the DejaVu fonts. The `pip install` line in `demo.gif` lists the installed versions of decisis and its dependencies, so draw it again after each release, in an environment where that release is installed:

```
decisis demo --out /tmp/demo-out > /tmp/demo.txt
python make_media.py docs/media /tmp/demo.txt
```
