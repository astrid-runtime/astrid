# Content-addressed objects

Objects are addressed by their tagged digest and are immutable.  Artifact
mirrors may add a new HTTPS locator through a signed `AddMirror` body, but the
bytes, size, media type, and digest set remain those of the publication.  Do
not publish an object under a digest that does not match its bytes.
