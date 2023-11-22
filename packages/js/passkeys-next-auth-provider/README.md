# Hanko Passkeys Auth.js Provider

If you already have a Next.js set up with Auth.js, you can easily passkeys to your app using `@teamhanko/passkeys-next-auth-provider`.

```bash
npm install @teamhanko/passkeys-next-auth-provider
```

In your `pages/api/auth/[...nextauth].ts`:

```ts
import { tenant, PasskeyProvider } from "@teamhanko/passkeys-next-auth-provider";

export default NextAuth({
	providers: [
		PasskeyProvider({
			tenant: tenant({
				tenantId: "<your tenant id>",
				apiKey: "<your secret api key>",
			}),
			async authorize({ userId }) {
				const user = db.users.find(userId);

				// Do more stuff

				return {
					id: user.id,
					name: user.username,
				};
			},
		}),
	],
});
```

In one of your components:

```jsx
import { signInWithPasskey } from "@teamhanko/passkeys-next-auth-provider";

export default LoginButton() {
	return (
		<button onClick={() => signInWithPasskey({ tenantId: "<your tenant id>" })} />
	);
}
```

**If you're using Hanko Cloud,** you can <a href="https://cloud.hanko.io/" target="_blank">get your tenant ID from your dashboard</a>.

If you're not using Hanko Cloud:

1. make sure to pass the `baseUrl` to both  
   `tenant` (in `[...nextauth].ts`) and  
   `signInWithPasskey()` (in your component).

2. get your tenant ID via the admin API
