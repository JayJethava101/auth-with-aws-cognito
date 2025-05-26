import { Injectable } from '@nestjs/common';
import { RabbitMqService } from 'src/rabbit-mq/rabbit-mq.service';

@Injectable()
export class NotificationService {
  constructor(private rabbitMQService: RabbitMqService) {}

  async onModuleInit() {
    this.rabbitMQService.subscribe(
      'order-notification',
      this.sendNotification.bind(this),
    );

     this.rabbitMQService.subscribe(
      'user.created',
      this.userCreatedNotification.bind(this),
    );
  }

  async sendNotification(order: object) {
    // Logic to send notification based on the order details
    console.log('🔔 sendNotification is called...', order);
  }

  async userCreatedNotification(user: object) {
    console.log('🔔 New user created ', user);
  }
}
