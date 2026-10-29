import { test, expect } from "vitest";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createRuntimeIdleCheck } from "./runtime-idle-state.js";

test(
  "a native idle process is retained while a background shell child survives",
  { skip: process.platform !== "linux" },
  async () => {
    const child = spawn(
      process.execPath,
      [
        "-e",
        `
    const {spawn}=require('node:child_process');let job;
    process.on('message',message=>{
      if(message==='start'){job=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});job.once('spawn',()=>process.send({started:job.pid}));}
      if(message==='stop'){job.once('close',()=>process.send({stopped:true}));job.kill('SIGTERM');}
    });
    process.on('SIGTERM',()=>{job?.kill('SIGTERM');process.exit(0);});process.send({ready:true});
  `,
      ],
      { stdio: ["ignore", "ignore", "ignore", "ipc"] },
    );
    const closed = once(child, "close");
    const idle = createRuntimeIdleCheck(child);
    try {
      await once(child, "message");
      expect(idle()).toBe("idle");
      const started = once(child, "message");
      child.send("start");
      await started;
      expect(idle()).toBe("unknown");
      const stopped = once(child, "message");
      child.send("stop");
      await stopped;
      expect(idle()).toBe("idle");
    } finally {
      child.kill("SIGTERM");
      await closed;
    }
    expect(idle()).toBe("unknown");
  },
);
