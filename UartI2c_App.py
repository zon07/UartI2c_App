import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, messagebox, Menu
from enum import IntEnum
import threading
import queue
import time

class Command(IntEnum):
    I2C_WRITE = 0x01
    I2C_READ = 0x02  # CMD_I2C_WRITE_THEN_READ
    GPIO_READ = 0x10
    GPIO_WRITE = 0x11
    PING = 0xFF

class Status(IntEnum):
    OK = 0x00
    ERROR = 0x01
    CRC_ERROR = 0x02

class UARTI2CTester:
    def __init__(self):
        self.ser = None
        self.use_crc = True
        self.rx_queue = queue.Queue()
        self.running = False

    def calculate_crc(self, current_crc, new_byte):
        crc = current_crc ^ new_byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) if (crc & 0x80) else (crc << 1)
        return crc & 0xFF

    def connect(self, port, baudrate=9600):
        try:
            self.ser = serial.Serial(port, baudrate, timeout=1)
            self.running = True
            threading.Thread(target=self._read_thread, daemon=True).start()
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться: {e}")
            return False

    def disconnect(self):
        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()

    def _read_thread(self):
        """Поток для чтения данных из порта"""
        buffer = bytes()
        while self.running:
            try:
                if self.ser.in_waiting > 0:
                    buffer += self.ser.read(self.ser.in_waiting)
                    
                    # Поиск пакетов в буфере
                    while len(buffer) >= 5:
                        start = buffer.find(b'\x41\x41')
                        if start == -1:
                            buffer = bytes()
                            break
                        
                        buffer = buffer[start:]
                        if len(buffer) < 5:
                            break
                        
                        length = buffer[2]
                        if len(buffer) < 3 + length + (1 if self.use_crc else 0):
                            break
                        
                        packet = buffer[:3 + length + (1 if self.use_crc else 0)]
                        buffer = buffer[3 + length + (1 if self.use_crc else 0):]
                        
                        if self.use_crc:
                            crc = 0
                            crc = self.calculate_crc(crc, length)
                            for byte in packet[3:3+length]:
                                crc = self.calculate_crc(crc, byte)
                            if packet[-1] != crc:
                                self.rx_queue.put(("ERROR", "CRC mismatch"))
                                continue
                        
                        payload = packet[3:3+length]
                        self.rx_queue.put(("DATA", payload))
            except Exception as e:
                self.rx_queue.put(("ERROR", str(e)))
                break

    def send_packet(self, packet_id, cmd, data=None):
        """Отправка пакета с CRC с задержкой между байтами"""
        if not self.ser or not self.ser.is_open:
            return False
        
        # Формируем payload
        if data:
            payload = bytes([packet_id, cmd]) + data
        else:
            payload = bytes([packet_id, cmd])
        
        # Добавляем заголовок и CRC
        packet = bytes([0x41, 0x41, len(payload)]) + payload
        
        if self.use_crc:
            crc = 0
            crc = self.calculate_crc(crc, len(payload))
            for byte in payload:
                crc = self.calculate_crc(crc, byte)
            packet += bytes([crc])
        
        try:
            # Отправка с задержкой 1 мс между байтами
            for byte in packet:
                self.ser.write(bytes([byte]))
                time.sleep(0.002)  # 1 мс задержка
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка отправки: {e}")
            return False

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("UART-I2C Bridge Tester")
        self.geometry("700x500")
        self.tester = UARTI2CTester()
        
        self.create_widgets()
        self.create_context_menu()
        self.after(100, self.process_events)

    def create_widgets(self):
        # Панель подключения
        self.connection_frame = ttk.LabelFrame(self, text="Подключение")
        self.connection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.port_label = ttk.Label(self.connection_frame, text="Порт:")
        self.port_label.grid(row=0, column=0, padx=5)
        
        self.port_combobox = ttk.Combobox(self.connection_frame)
        self.port_combobox.grid(row=0, column=1, padx=5)
        self.refresh_ports()
        
        self.refresh_ports_btn = ttk.Button(
            self.connection_frame,
            text="Обновить порты",
            command=self.refresh_ports
        )
        self.refresh_ports_btn.grid(row=0, column=2, padx=5)
        
        self.connect_btn = ttk.Button(
            self.connection_frame, 
            text="Подключиться", 
            command=self.toggle_connection
        )
        self.connect_btn.grid(row=0, column=3, padx=5)
        
        # Вкладки
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка I2C
        self.i2c_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.i2c_frame, text="I2C")
        self.create_i2c_tab()
        
        # Вкладка GPIO
        self.gpio_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.gpio_frame, text="GPIO")
        self.create_gpio_tab()
        
        # Лог
        self.log_frame = ttk.LabelFrame(self, text="Лог")
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(self.log_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Кнопки управления логом
        btn_frame = ttk.Frame(self.log_frame)
        btn_frame.pack(side=tk.RIGHT, padx=5, pady=5)
        
        self.copy_log_btn = ttk.Button(
            btn_frame,
            text="Копировать лог",
            command=self.copy_log
        )
        self.copy_log_btn.pack(side=tk.TOP, pady=2)
        
        self.clear_log_btn = ttk.Button(
            btn_frame,
            text="Очистить лог",
            command=self.clear_log
        )
        self.clear_log_btn.pack(side=tk.TOP, pady=2)

    def create_context_menu(self):
        """Создание контекстного меню для лога"""
        self.log_menu = Menu(self, tearoff=0)
        self.log_menu.add_command(label="Копировать", command=self.copy_log)
        self.log_menu.add_command(label="Очистить", command=self.clear_log)
        
        self.log_text.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Показ контекстного меню"""
        try:
            self.log_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.log_menu.grab_release()

    def create_i2c_tab(self):
        # I2C Write
        self.i2c_write_frame = ttk.LabelFrame(self.i2c_frame, text="I2C Запись")
        self.i2c_write_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.i2c_write_frame, text="Адрес (hex):").grid(row=0, column=0)
        self.i2c_addr_entry = ttk.Entry(self.i2c_write_frame, width=10)
        self.i2c_addr_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(self.i2c_write_frame, text="Команда (hex):").grid(row=1, column=0)
        self.i2c_cmd_entry = ttk.Entry(self.i2c_write_frame, width=10)
        self.i2c_cmd_entry.grid(row=1, column=1, padx=5)
        
        ttk.Label(self.i2c_write_frame, text="Данные (hex):").grid(row=2, column=0)
        self.i2c_data_entry = ttk.Entry(self.i2c_write_frame, width=30)
        self.i2c_data_entry.grid(row=2, column=1, padx=5)
        
        self.i2c_write_btn = ttk.Button(
            self.i2c_write_frame,
            text="Отправить",
            command=self.i2c_write
        )
        self.i2c_write_btn.grid(row=2, column=2, padx=5)
        
        # I2C Read
        self.i2c_read_frame = ttk.LabelFrame(self.i2c_frame, text="I2C Чтение")
        self.i2c_read_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.i2c_read_frame, text="Адрес (hex):").grid(row=0, column=0)
        self.i2c_read_addr_entry = ttk.Entry(self.i2c_read_frame, width=10)
        self.i2c_read_addr_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(self.i2c_read_frame, text="Команда (hex):").grid(row=1, column=0)
        self.i2c_read_cmd_entry = ttk.Entry(self.i2c_read_frame, width=10)
        self.i2c_read_cmd_entry.grid(row=1, column=1, padx=5)
        
        ttk.Label(self.i2c_read_frame, text="Байт для чтения:").grid(row=2, column=0)
        self.i2c_read_len_entry = ttk.Entry(self.i2c_read_frame, width=5)
        self.i2c_read_len_entry.insert(0, "1")
        self.i2c_read_len_entry.grid(row=2, column=1, padx=5)
        
        self.i2c_read_btn = ttk.Button(
            self.i2c_read_frame,
            text="Прочитать",
            command=self.i2c_read
        )
        self.i2c_read_btn.grid(row=2, column=2, padx=5)
        
        # Ping
        self.ping_btn = ttk.Button(
            self.i2c_frame,
            text="Ping",
            command=self.send_ping
        )
        self.ping_btn.pack(pady=5)

    def create_gpio_tab(self):
        # GPIO Read
        self.gpio_read_frame = ttk.LabelFrame(self.gpio_frame, text="Чтение GPIO")
        self.gpio_read_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.gpio_read_frame, text="Выберите пин:").grid(row=0, column=0, padx=5)
        
        self.gpio_pin_var = tk.StringVar()
        self.gpio_pin_combobox = ttk.Combobox(
            self.gpio_read_frame,
            textvariable=self.gpio_pin_var,
            values=["0 - Bsp_PrstPort", "1 - Bsp_VD2", "2 - Bsp_PwrOnPort"],
            state="readonly",
            width=20
        )
        self.gpio_pin_combobox.current(0)
        self.gpio_pin_combobox.grid(row=0, column=1, padx=5)
        
        self.gpio_read_btn = ttk.Button(
            self.gpio_read_frame,
            text="Прочитать",
            command=self.gpio_read
        )
        self.gpio_read_btn.grid(row=0, column=2, padx=5)
        
        # GPIO Write
        self.gpio_write_frame = ttk.LabelFrame(self.gpio_frame, text="Запись GPIO")
        self.gpio_write_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.gpio_write_frame, text="Выберите пин:").grid(row=0, column=0, padx=5)
        
        self.gpio_write_pin_var = tk.StringVar()
        self.gpio_write_pin_combobox = ttk.Combobox(
            self.gpio_write_frame,
            textvariable=self.gpio_write_pin_var,
            values=["1 - Bsp_VD2", "2 - Bsp_PwrOnPort"],
            state="readonly",
            width=20
        )
        self.gpio_write_pin_combobox.current(0)
        self.gpio_write_pin_combobox.grid(row=0, column=1, padx=5)
        
        ttk.Label(self.gpio_write_frame, text="Состояние:").grid(row=1, column=0, padx=5)
        
        self.gpio_state_var = tk.IntVar(value=1)
        ttk.Radiobutton(
            self.gpio_write_frame,
            text="Включить (1)",
            variable=self.gpio_state_var,
            value=1
        ).grid(row=1, column=1, sticky=tk.W)
        
        ttk.Radiobutton(
            self.gpio_write_frame,
            text="Выключить (0)",
            variable=self.gpio_state_var,
            value=0
        ).grid(row=2, column=1, sticky=tk.W)
        
        self.gpio_write_btn = ttk.Button(
            self.gpio_write_frame,
            text="Установить",
            command=self.gpio_write
        )
        self.gpio_write_btn.grid(row=3, column=1, pady=5)

    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combobox['values'] = ports
        if ports:
            self.port_combobox.set(ports[0])

    def toggle_connection(self):
        if self.tester.ser and self.tester.ser.is_open:
            self.tester.disconnect()
            self.connect_btn.config(text="Подключиться")
            self.log("Отключено от порта")
        else:
            port = self.port_combobox.get()
            if port and self.tester.connect(port):
                self.connect_btn.config(text="Отключиться")
                self.log(f"Подключено к {port}")

    def i2c_write(self):
        try:
            addr = int(self.i2c_addr_entry.get(), 16)
            cmd = int(self.i2c_cmd_entry.get(), 16)
            data = bytes.fromhex(self.i2c_data_entry.get()) if self.i2c_data_entry.get() else bytes()
            
            # Формат: [SA][I2C_DATA_LEN][I2C_CMD(2)][I2C_WRITE_DATA]
            cmd_bytes = bytes([(cmd >> 8) & 0xFF, cmd & 0xFF])  # Старший байт первым
            write_len = len(data)
            data_part = bytes([addr, write_len]) + cmd_bytes + data
            
            if self.tester.send_packet(1, Command.I2C_WRITE, data_part):
                self.log(f"I2C Write -> Адрес: 0x{addr:02x}, Команда: 0x{cmd:04x}, Длина: {write_len}, Данные: {data.hex(' ') if data else 'нет'}")
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректные данные: {e}")

    def i2c_read(self):
        try:
            addr = int(self.i2c_read_addr_entry.get(), 16)
            cmd = int(self.i2c_read_cmd_entry.get(), 16)
            length = int(self.i2c_read_len_entry.get())
            
            # Формат: [SA][I2C_DATA_LEN][I2C_CMD(2)]
            cmd_bytes = bytes([(cmd >> 8) & 0xFF, cmd & 0xFF])  # Старший байт первым
            data_part = bytes([addr, length]) + cmd_bytes
            
            if self.tester.send_packet(1, Command.I2C_READ, data_part):
                self.log(f"I2C Read -> Адрес: 0x{addr:02x}, Команда: 0x{cmd:04x}, Байт для чтения: {length}")
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректные данные: {e}")

    def gpio_read(self):
        try:
            pin_str = self.gpio_pin_var.get()
            pin = int(pin_str.split(" - ")[0])
            
            if self.tester.send_packet(1, Command.GPIO_READ, bytes([pin])):
                self.log(f"GPIO Read -> Пин: {pin_str}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка чтения GPIO: {e}")

    def gpio_write(self):
        try:
            pin_str = self.gpio_write_pin_var.get()
            pin = int(pin_str.split(" - ")[0])
            state = self.gpio_state_var.get()
            
            if self.tester.send_packet(1, Command.GPIO_WRITE, bytes([pin, state])):
                self.log(f"GPIO Write -> Пин: {pin_str}, Состояние: {'Вкл' if state else 'Выкл'}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка записи GPIO: {e}")

    def send_ping(self):
        # Ping остается без изменений
        if self.tester.send_packet(1, Command.PING):
            self.log("Ping ->")

    def process_events(self):
        while not self.tester.rx_queue.empty():
            event_type, data = self.tester.rx_queue.get()
            
            if event_type == "DATA":
                if len(data) >= 3:
                    packet_id = data[0]
                    cmd = data[1]
                    status_or_value = data[2]
                    
                    # Форматируем статус
                    status_text = ""
                    try:
                        if cmd == Command.GPIO_READ:
                            status_text = "HIGH" if status_or_value else "LOW"
                        else:
                            status_text = Status(status_or_value).name
                    except ValueError:
                        status_text = f"0x{status_or_value:02x}"
                    
                    # Формируем сообщение
                    message = [
                        f"Получен пакет:",
                        f"ID Пакета: 0x{packet_id:02x}",
                        f"Команда: 0x{cmd:02x} ({Command(cmd).name if cmd in Command._value2member_map_ else 'НЕИЗВЕСТНА'})",
                        f"Статус: {status_text}"
                    ]
                    
                    # Добавляем специфичную информацию
                    if cmd == Command.PING:
                        message.append("Тип: Ответ на Ping")
                    
                    elif cmd == Command.I2C_WRITE:
                        message.append("Операция: Запись I2C")
                    
                    elif cmd == Command.I2C_READ:
                        if status_or_value == Status.OK and len(data) > 3:
                            message.append(f"Данные: {data[3:].hex(' ')}")
                        else:
                            message.append("Результат: Ошибка чтения")
                    
                    elif cmd == Command.GPIO_READ:
                        pin = data[0] if len(data) > 0 else 0
                        message.append(f"Пин: {pin}")
                        message.append(f"Состояние: {'HIGH' if status_or_value else 'LOW'}")
                    
                    elif cmd == Command.GPIO_WRITE:
                        message.append("Операция: Запись GPIO")
                    
                    # Выводим сообщение с разделителями
                    for line in message:
                        self.log(line)
                    self.log("")  # Пустая строка как разделитель
            
            elif event_type == "ERROR":
                self.log(f"Ошибка: {data}")
                self.log("")  # Пустая строка после ошибки
        
        self.after(100, self.process_events)

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def copy_log(self):
        """Копирование содержимого лога в буфер обмена"""
        self.clipboard_clear()
        self.clipboard_append(self.log_text.get(1.0, tk.END))
        self.log("Лог скопирован в буфер обмена")

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def on_closing(self):
        self.tester.disconnect()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()