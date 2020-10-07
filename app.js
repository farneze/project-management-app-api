const express = require("express");
const cors = require("cors");

const app = express();

// Configura o app para entender requisições com tipo de corpo JSON
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000" }));

const projectRouter = require("./routes/project.routes");
const taskRouter = require("./routes/task.routes");
const authRouter = require("./routes/auth.routes");

require("./configs/db.config");

// Configurar passport
require("./configs/passport.config")(app);

app.use("/api", projectRouter);
app.use("/api", taskRouter);
app.use("/api", authRouter);

app.listen(4000, () => console.log("running at port 4000"));
