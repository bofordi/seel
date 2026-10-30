// Deploy with: supabase functions deploy create-manager
// Set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY automatically in Supabase Edge Functions.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return new Response("Unauthorized", { status: 401 });
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const tokenClient = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: authHeader } }
  });
  const { data: { user }, error: userError } = await tokenClient.auth.getUser();
  if (userError || !user) return new Response("Unauthorized", { status: 401 });
  const { data: actor } = await admin.from("profiles").select("role").eq("id", user.id).single();
  if (actor?.role !== "admin") return new Response("Forbidden", { status: 403 });
  const { email, password, display_name, role } = await req.json();
  if (!email || !password || password.length < 8 || !["support_manager","buyback_manager","product_manager"].includes(role)) {
    return Response.json({ error: "Invalid input" }, { status: 400 });
  }
  const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { display_name } });
  if (error) return Response.json({ error: error.message }, { status: 400 });
  const { error: profileError } = await admin.from("profiles").update({ role, display_name }).eq("id", data.user.id);
  if (profileError) return Response.json({ error: profileError.message }, { status: 500 });
  return Response.json({ id: data.user.id, email });
});
