# Jellyfin sign-in for Shelfarr

This unofficial Rails extension adds a separate **Sign in with Jellyfin** form to Shelfarr. Existing Shelfarr users use the standard form. A successful Jellyfin sign-in provisions a regular Shelfarr account and binds it to the Jellyfin user ID. If an active local account already has the same username, including after normalization, it keeps its own Shelfarr sign-in and the extension blocks Jellyfin account creation. Deleting a Shelfarr account frees its username for a fresh Jellyfin-linked account with the regular user role.

## Install from GitHub

1. Set up a local Shelfarr administrator and back up the Shelfarr storage volume. Keep **Disable password authentication** off, including the `DISABLE_AUTH` environment variable. Disable OIDC auto-redirect to show the password form by default. With auto-redirect enabled, use Shelfarr’s local sign-in link to reach the Jellyfin option.
2. Add `extends` and the Jellyfin environment settings to the existing `shelfarr` service in your Compose file. Keep your existing image, volumes, and network settings. When switching from a ZIP install, remove the previous adapter bind mounts so Compose uses the GitHub copies.

   ```yaml
   services:
     shelfarr:
       extends:
         file: https://github.com/karyeet/shelfarr-jellyfin-login.git#v0.1.1:docker-compose.override.yml
         service: shelfarr
       environment:
         JELLYFIN_AUTH_URL: "https://jellyfin.example.net"
   ```

   Compose fetches the tagged Git checkout and mounts the extension files read-only into the stock Shelfarr container. Configuration and file resolution were verified with Docker Compose 5.7.0. For a Compose version without Git-backed `extends`, use the ZIP install below. When using a remote Docker daemon, keep the files on the Docker host and use the ZIP install there. [Docker Compose extends documentation](https://docs.docker.com/compose/how-tos/multiple-compose-files/extends/) · [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)

3. Set `JELLYFIN_AUTH_URL` to the base URL reachable by the Shelfarr container and include any Jellyfin path prefix. HTTPS requires a trusted certificate matching the hostname. For a trusted private HTTP connection, use the environment block below.

4. Serve Shelfarr over HTTPS. If you terminate TLS at a reverse proxy, have it set `X-Forwarded-Proto: https` for HTTPS requests and keep the backend Shelfarr port private. Use a Shelfarr image version you have tested with the extension. Its Rails controller hooks were reviewed against `2026.11.09.1` and tested against `2026.11.16.1`.
5. From the Compose directory, validate the combined configuration and recreate the Shelfarr service.

   ```bash
   docker compose config --quiet
   docker compose up -d --no-deps shelfarr
   docker compose logs --tail=100 shelfarr
   ```

6. Test your local administrator first. Then choose **Sign in with Jellyfin** and enter the actual Jellyfin username and password of a regular test user. Check the first sign-in, logout, repeat sign-in, wrong-password rejection, and Shelfarr two-factor verification if you use it.

To publish your own GitHub release, put the contents of the release ZIP at the root of a repository you control and push a Git tag such as `v0.1.1`. The Compose URL refers to that Git tag. The three extension files and `docker-compose.override.yml` belong in the same directory.

### Install from the ZIP

Extract the release ZIP and copy its initializer, view, migration, and `docker-compose.override.yml` beside your existing Compose file. If you already have a Compose override, merge the three read-only mounts into its `shelfarr` service. Add the Jellyfin environment settings to your Compose service and follow the restart steps above. Shelfarr applies the migration at startup.

### Private HTTP between Shelfarr and Jellyfin

If both services share a trusted private Docker network and the Jellyfin service is named `jellyfin`, use this environment block under `services.shelfarr`. Use the Jellyfin service name or its private address as seen from Shelfarr.

```yaml
environment:
  JELLYFIN_AUTH_URL: "http://jellyfin:8096"
  JELLYFIN_ALLOW_PRIVATE_HTTP: "true"
```

The browser still uses HTTPS to reach Shelfarr. Passwords and Jellyfin tokens cross the Shelfarr-to-Jellyfin connection without encryption. Use this setting only on a network you control and trust. The adapter accepts only private or loopback destinations in HTTP mode.

## Account and session behavior

- Jellyfin verifies the submitted password. Shelfarr keeps a random local password digest for the account and issues its own session. The adapter requests Jellyfin token revocation immediately after authentication and logs a warning if that request fails.
- By default, any user who can authenticate to the configured Jellyfin server through this connection is eligible for an ordinary Shelfarr account. Existing Shelfarr sessions and API tokens follow Shelfarr’s own expiration and revocation rules, even after a Jellyfin account is disabled.
- Shelfarr’s two-factor challenge works for Jellyfin accounts and expires after five minutes. The challenge uses Shelfarr’s configured cache to rate-limit attempts by account. While the adapter is enabled, Shelfarr records accepted authenticator codes and consumes backup codes under a database lock for both local and Jellyfin sign-ins. Shelfarr’s profile actions for regenerating backup codes or disabling two-factor authentication still require a local password. Arrange recovery with your Shelfarr administrator before depending on this feature.
- Jellyfin users sign in with their Jellyfin names, including spaces. Shelfarr normalizes those names for local display and lookup. A name that belongs to an active Shelfarr account or normalizes to an empty value blocks automatic provisioning. Empty Jellyfin passwords are rejected.

## Rollback

Remove the extension’s `extends` block or its three bind mounts and environment entries, then run `docker compose up -d --no-deps shelfarr`. Jellyfin-created records stay in Shelfarr and need another sign-in method. The database retains the column added by the migration.

## Smoke tests

Run `ruby test_adapter.rb` and `ruby test_sessions_override.rb` from this directory with Minitest installed.

For the database-backed regression tests, copy `test_otp_replay.rb` into the Shelfarr checkout under `test/models/`. With the initializer enabled and the migration applied, run `bin/rails test test/models/test_otp_replay.rb` from that checkout.
