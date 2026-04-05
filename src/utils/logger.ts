/**
 * Centralized Logger Utility
 * Provides a standardized way to log messages with timestamps
 */

class Logger {
  private getTimestamp(): string {
    return new Date().toISOString();
  }

  private formatMessage(level: string, message: string): string {
    return `[${this.getTimestamp()}] [${level}] ${message}`;
  }

  info(message: string, ...args: any[]): void {
    console.log(this.formatMessage('INFO', message), ...args);
  }

  warn(message: string, ...args: any[]): void {
    console.warn(this.formatMessage('WARN', message), ...args);
  }

  error(message: string, ...args: any[]): void {
    console.error(this.formatMessage('ERROR', message), ...args);
  }

  debug(message: string, ...args: any[]): void {
    if (process.env.DEBUG) {
      console.debug(this.formatMessage('DEBUG', message), ...args);
    }
  }
}

export const logger = new Logger();
export default logger;
