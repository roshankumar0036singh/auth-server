# Changelog

## [2.0.0] - 2026-06-21

### Changed
- **BREAKING**: `AdminClient.listUsers()` now returns a paginated structure containing `{ users, meta }` instead of a flat array of users.

**Migration Guide**:
```typescript
// Old
const users = await admin.listUsers();

// New
const { users } = await admin.listUsers();
```
