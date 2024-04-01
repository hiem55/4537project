import { compareSync } from "bcrypt";
import { sign } from "jsonwebtoken";
import { setCookie } from "cookies";

export default async function handle(req, res) {
    if (req.method === "POST") {
        // Login user
        await loginUserHandler(req, res);
    } else {
        return res.status(405).end();
    }
}

async function loginUserHandler(req, res) {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "Invalid inputs" });
    }
    try {
        const user = await prisma.user.findUnique({
            where: { email: email },
            select: {
                id: true,
                name: true,
                email: true,
                password: true,
            },
        });
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        if (!compareSync(password, user.password)) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        // Generate JWT token
        const token = sign({ userId: user.id }, process.env.SECRET_KEY, { expiresIn: "1h" });
        // Set HTTP-only cookie with JWT token
        setCookie(res, "token", token);
        // Exclude password from JSON response
        delete user.password;
        return res.status(200).json(user);
    } catch (e) {
        console.error("Error:", e);
        return res.status(500).json({ message: "Internal server error" });
    }
}
