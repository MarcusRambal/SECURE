import asyncio
import json
import uuid
from datetime import datetime, timezone

import aio_pika


async def main():
    task_id = str(uuid.uuid4())
    target_url = "http://juice-shop:3000"
    attack_type = "crypto_inspector"
    queued_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "task_id": task_id,
        "target_url": target_url,
        "attack_type": attack_type,
        "queued_at": queued_at,
    }

    connection = await aio_pika.connect_robust(
        "amqp://marcus:CampanaPlateada1902@localhost:5672/"
    )
    async with connection:
        channel = await connection.channel()
        queue = await channel.declare_queue("orchestrator_queue", durable=True)
        await queue.purge()
        message = aio_pika.Message(
            body=json.dumps(payload).encode("utf-8"),
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )
        await channel.default_exchange.publish(
            message,
            routing_key="orchestrator_queue",
        )
        print(f"PUBLICATED task_id={task_id} attack_type={attack_type}")

    await connection.close()


asyncio.run(main())
