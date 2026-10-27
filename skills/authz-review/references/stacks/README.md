# Stack notes

One file per stack. Each file says where authorization usually lives and what a missing check looks like.
Planned, written from real reviews rather than in advance:

- `nestjs.md`: guards, `@UseGuards`, service-layer ownership checks, `ValidationPipe` `whitelist`
- `express.md`: middleware order, `req.user`
- `nuxt.md`: `server/api` routes, server middleware vs client-only route guards
- `supabase.md`: RLS policies, `service_role` key in the client
- `firebase.md`: Firestore and Storage security rules
- `flutter.md`: checks done only in the app, API keys in the build
