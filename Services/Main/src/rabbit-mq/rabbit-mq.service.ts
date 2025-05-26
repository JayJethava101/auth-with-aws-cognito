import { Injectable } from '@nestjs/common';
import { connect, Channel, Connection } from 'amqplib';

@Injectable()
export class RabbitMqService {
  private connection: Connection;
  private channel: Channel;
  private initialized = false;
  private initPromise: Promise<void>;

  constructor() {
    this.initPromise = this.init();
  }

  private async init() {
    if (this.connection && this.channel) {
      console.log('RabbitMq connection already established.');
      return;
    }

    this.connection = await connect(process.env.RABBITMQ_URL);
    this.channel = await this.connection.createChannel();
    this.initialized = true;
    console.log('RabbitMq connection established successfully');
  }

  async publish(queue: string, message: any) {
    await this.ensureInitialized();
    this.channel.assertQueue(queue);
    this.channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)));
  }

  async subscribe(queue: string, callback: (message: any) => void) {
    await this.ensureInitialized();
    this.channel.assertQueue(queue);
    this.channel.consume(queue, (msg) => {
      if (msg !== null) {
        callback(JSON.parse(msg.content.toString()));
        this.channel.ack(msg);
      }
    });
    console.log(`Successfully subscribed to rabbitmq queue: ${queue}`);
  }

  private async ensureInitialized() {
    if (!this.initialized) {
      await this.initPromise;
    }
  }
}
