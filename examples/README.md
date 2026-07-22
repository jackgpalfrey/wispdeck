# Example site bundle

`wispdeck-demo-site.zip` is ready to upload from the Hosted sites section of
the Wispdeck dashboard. It contains a responsive homepage, a nested `/about/`
page, shared CSS, and a live shared checklist backed by
Wispist. Open it in two browsers to see checklist changes arrive without a
refresh.

The unpacked source is in `demo-site/`. To rebuild the archive from that
directory:

```sh
zip -FS ../wispdeck-demo-site.zip \
  index.html styles.css app.js wispist.json about/index.html
```

The archive contents, rather than the `demo-site` directory itself, must be at
the ZIP root so that `index.html` is a root entry.
