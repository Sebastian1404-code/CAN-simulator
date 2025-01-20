import tkinter as tk
from tkinter import messagebox,filedialog
import time
import json
#version 3
class Wire:
    def __init__(self):
        self.no_nodes = 3
        self.time = 0
        self.nodes = []
        self.info = {}
        self.current_wire_state = None

    def add_node(self, node):
        self.nodes.append(node)

    def running_wire(self,duration):
        while self.time <= duration:
            self.update_output(f"Time: {self.time}")
            for node in self.nodes:
                stop_action=node.verify(self.time)
                if stop_action==True:
                    for node in self.nodes:
                        node.verify(self.time)
                    break
            self.current_wire_state = self.compute_wire_state()
            for node in self.nodes:
                node.arbitration()
            self.show_data()
            self.info.clear()
            self.time += 1

    def insert_info(self, node_id, bit):
        self.info[node_id] = bit

    def compute_wire_state(self):
        bit_values = [value[0] for value in self.info.values()]
        if 0 in bit_values:
            return 0
        elif 1 in bit_values:
            return 1
        else:
            return None

    def show_data(self):
        self.update_output(f"Wire State: {self.current_wire_state}")
        for key in self.info:
            self.update_output(f"Node: {key}, Bit: {self.info[key][0]} ({self.info[key][1]})")


    def update_output(self, message):
        app.output_text.insert(tk.END, message + "\n")
        app.output_text.yview(tk.END)
        try:
            with open("output.txt", "a") as file:  # Open file in write mode (overwrites existing file)
                file.write(message+"\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save output: {e}")
    
    def clear_output_file(self):
        try:
            with open("output.txt", "w") as file:
                file.write("") 
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear output file: {e}")


class Node:
    def __init__(self, node_id, wire, node_output, node_text_widgets):
        self.node_id = node_id
        self.messages = []
        self.wire = wire
        self.current_message = None
        self.bit = None
        self.blocked = False
        self.node_output = node_output
        self.node_text_widgets = node_text_widgets

    def add_message(self, message):
        self.messages.append(message)

    def verify(self, time):
        if self.current_message and self.current_message.is_complete():
            if self.current_message.verify_crc():  # Verify CRC before processing the message
                self.message_complete(self.current_message)
                self.wire.update_output(f"Finish message from Node {self.node_id}")
            else:
                self.wire.update_output(f"Error frame: Node {self.node_id} detected a CRC error.")
            self.delete_message(self.current_message)
            self.current_message = None
            self.wire.info.clear()
            for node in self.wire.nodes:
                node.blocked = False
            return True
        if self.current_message is None:
            for message in self.messages:
                if time >= message.get_time():
                    self.current_message = message
                    break
        if self.current_message:
            self.transmit()
        return False

    def delete_message(self, message):
        if message in self.messages:
            self.messages.remove(message)

    def transmit(self):
        if self.blocked == False:
            if self.current_message:
                self.bit, bit_type = self.current_message.transmit_next_bit()
                self.wire.insert_info(self.node_id, (self.bit, bit_type))

    def message_complete(self, message):
        selected_node_id = message.selected_node
        selected_node_output = self.node_text_widgets[int(selected_node_id) - 1]
        selected_node_output.insert(tk.END, f"Message from Node {self.node_id}: {message}\n")

    def arbitration(self):
        if self.blocked == False:
            if self.wire.current_wire_state is not None:
                if self.current_message is not None:
                    if self.bit != self.wire.current_wire_state:
                        self.blocked = True
                        self.current_message.reset()
                        self.wire.info.pop(self.node_id, None) #modified
                else:
                    self.blocked = True

    def __repr__(self):
        return f"CANNode(node_id={self.node_id}, messages={self.messages})"


class CANMessage:
    def __init__(self, time, node_id, dlc, data, crc,selected_node):
        if not (0 <= crc <= 15):
            raise ValueError("CRC must be a 4-bit value (0 to 15).")
        self.time = time
        self.start = 0
        self.identifier = f"{node_id:03b}"
        self.dlc = f"{dlc:02b}"
        self.data = data
        self.eof = 1
        self.index = 0
        self.selected_node = selected_node
        self.crc=crc

    def __repr__(self):
        return (f"CANMessage(time={self.time}, start={self.start}, "
                f"id={self.identifier}, dlc={self.dlc}, data={self.data}, eof={self.eof}, crc={self.crc:04b})")


    def get_time(self):
        return self.time

    def transmit_next_bit(self):
        total_bits = 1 + 3 + 2 + len(self.data) + 1 + 4  # SOF, ID, DLC, DATA, EOF, CRC
        if self.index == 0:
            bit = self.start
            bit_type = "SOF"
        elif 1 <= self.index <= 3:
            bit = int(self.identifier[self.index - 1])
            bit_type = "ID"
        elif 4 <= self.index <= 5:
            bit = int(self.dlc[self.index - 4])
            bit_type = "DLC"
        elif 6 <= self.index < 6 + len(self.data):
            bit = int(self.data[self.index - 6])
            bit_type = "DATA"
        elif 6 + len(self.data) <= self.index < 6 + len(self.data) + 4:  
            crc_index = self.index - (6 + len(self.data))  
            bit = (self.crc >> (3 - crc_index)) & 0b1  
            bit_type = "CRC"
        elif self.index == 6 + len(self.data) + 4:  
            bit = self.eof
            bit_type = "EOF"
        else:
            raise ValueError("Transmission index out of range.")
        self.index += 1
        return bit, bit_type
    


    def calculate_crc(self, polynomial=0b10011):
        frame_bits = self.identifier + self.dlc + self.data
        crc = 0  # Initialize CRC to 0
        for bit in frame_bits:
            crc ^= int(bit)  # XOR the current bit with the CRC
            for _ in range(4):  # Perform 4-bit CRC calculation
                if crc & 0b1000:  # Check if the MSB is 1
                    crc = (crc << 1) ^ polynomial  # XOR with polynomial
                else:
                    crc <<= 1
                crc &= 0b1111  # Keep only the lower 4 bits
        print(f"crc:{crc}")
        return crc

    def verify_crc(self):
        calculated_crc = self.calculate_crc()
        return calculated_crc == self.crc

    def reset(self):
        self.index = 0

    def is_complete(self):
        total_bits = 1 + 3 + 2 + len(self.data) + 1 + 4
        return self.index >= total_bits


class CANNodeConfigurator:
    def __init__(self, master):
        self.wire = Wire()
        self.master = master
        master.title("CAN Node Configuration")
        self.node_text_widgets = {}

        # Add an input field for simulation duration
        self.duration_frame = tk.Frame(master)
        self.duration_frame.pack(pady=10)

        self.duration_label = tk.Label(self.duration_frame, text="Simulation Duration :", font=("Arial", 10))
        self.duration_label.grid(row=0, column=0, padx=5)

        self.duration_entry = tk.Entry(self.duration_frame, font=("Arial", 10))
        self.duration_entry.grid(row=0, column=1, padx=5)
        self.duration_entry.insert(0, "100")  # Default value

        self.nodes = [self.create_node_frame(master, i) for i in range(3)]

        self.configure_button = tk.Button(master, text="Configure Nodes", command=self.configure_nodes)
        self.configure_button.pack(pady=10)

    
        self.load_scenario_button = tk.Button(master, text="Load Scenario from File", command=self.load_scenario_from_file)
        self.load_scenario_button.pack(pady=10)

        self.output_frame = tk.Frame(master)
        self.output_frame.pack(pady=10)

        self.output_text = tk.Text(self.output_frame, height=20, width=80)  # Adjusted size
        self.output_text.grid(row=0, column=0, padx=5)

        self.scrollbar = tk.Scrollbar(self.output_frame, command=self.output_text.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_text.configure(yscrollcommand=self.scrollbar.set)


        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle the GUI closing event."""
        self.wire.clear_output_file()  # Clear the output.txt file
        self.master.destroy() 

    def clear_output(self):
        """Clear the output text area."""
        self.output_text.delete(1.0, tk.END)

    def clear_node_outputs(self):
        for node in self.nodes:
            node["node_output"].delete(1.0, tk.END)

    def create_node_frame(self, master, node_id):
        node_frame = tk.Frame(master)
        node_frame.pack(pady=10)

        node_label = tk.Label(node_frame, text=f"Node {node_id + 1}", font=("Arial", 12))
        node_label.grid(row=0, column=0, padx=10)

        node_output = tk.Text(node_frame, height=5, width=40)
        node_output.grid(row=1, column=0, padx=10, pady=5)

        self.node_text_widgets[node_id] = node_output

        messages_entries = []
        add_message_button = tk.Button(node_frame, text="Add Message", command=lambda: self.add_message_entry(node_frame, messages_entries, node_id))
        add_message_button.grid(row=2, column=0, padx=10, pady=5)

        return {"node_id": node_id + 1, "node_frame": node_frame, "messages_entries": messages_entries, "node_output": node_output}

    def add_message_entry(self, node_frame, messages_entries, node_id):
        row = len(messages_entries) + 3
        entry_frame = tk.Frame(node_frame)
        entry_frame.grid(row=row, column=0, columnspan=6, pady=5, sticky="w")

        # Time field
        time_label = tk.Label(entry_frame, text="Time (Seconds):", font=("Arial", 10))
        time_label.grid(row=0, column=0, padx=5)
        time_entry = tk.Entry(entry_frame, font=("Arial", 10))
        time_entry.grid(row=0, column=1, padx=5)

        # DLC field
        dlc_label = tk.Label(entry_frame, text="DLC (Integer):", font=("Arial", 10))
        dlc_label.grid(row=0, column=2, padx=5)
        dlc_entry = tk.Entry(entry_frame, font=("Arial", 10))
        dlc_entry.grid(row=0, column=3, padx=5)

        # Data field
        data_label = tk.Label(entry_frame, text="Data (Bits):", font=("Arial", 10))
        data_label.grid(row=0, column=4, padx=5)
        data_entry = tk.Entry(entry_frame, font=("Arial", 10))
        data_entry.grid(row=0, column=5, padx=5)

        # CRC field
        crc_label = tk.Label(entry_frame, text="CRC (4-bit):", font=("Arial", 10))
        crc_label.grid(row=0, column=6, padx=5)
        crc_entry = tk.Entry(entry_frame, font=("Arial", 10))
        crc_entry.grid(row=0, column=7, padx=5)

        # Destination node dropdown
        selected_node_var = tk.StringVar()
        selected_node_var.set("1")  # Default to node 1
        node_dropdown = tk.OptionMenu(entry_frame, selected_node_var, "1", "2", "3")
        node_dropdown.grid(row=0, column=8, padx=5)

        # Store all input fields
        messages_entries.append({
            "time_entry": time_entry,
            "dlc_entry": dlc_entry,
            "data_entry": data_entry,
            "crc_entry": crc_entry,  # Include CRC entry
            "selected_node_var": selected_node_var 
        })

    def configure_nodes(self):
        self.node_instances = []
        self.output_text.delete(1.0, tk.END)
        self.clear_node_outputs() 

        # Get simulation duration from user input
        try:
            duration = int(self.duration_entry.get())
            if duration <= 0:
                raise ValueError("Duration must be a positive integer.")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid duration: {e}")
            return

        for node in self.nodes:
            node_id = node["node_id"]
            node_output = node["node_output"]
            can_node = Node(node_id, self.wire, node_output, self.node_text_widgets)

            for entry in node["messages_entries"]:
                try:
                    time = float(entry["time_entry"].get())
                    dlc = int(entry["dlc_entry"].get())
                    data = entry["data_entry"].get()
                    crc = int(entry["crc_entry"].get())  # Read CRC input
                    if not (0 <= crc <= 15):
                        raise ValueError(f"Invalid CRC for Node {node_id}. CRC must be a 4-bit value (0-15).")
                    if not all(bit in '01' for bit in data):
                        raise ValueError(f"Invalid data for Node {node_id}. Data should only contain bits (0 or 1).")
                    if len(data) != dlc:
                        raise ValueError(f"Invalid data length for Node {node_id}. DLC should match data length.")
                    selected_node = int(entry["selected_node_var"].get())
                    message = CANMessage(time, node_id, dlc, data, crc, selected_node)
                    can_node.add_message(message)
                except ValueError as e:
                    messagebox.showerror("Error", str(e))
                    return

            self.node_instances.append(can_node)

        for node in self.node_instances:
            self.wire.add_node(node)
        self.wire.time = 0
        self.wire.running_wire(duration)  # Pass duration to running_wire

    def load_scenario_from_file(self):
        """Load a scenario from a JSON file and run it."""
        # Open a file dialog to select the scenario file
        file_path = filedialog.askopenfilename(
            title="Select Scenario File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not file_path:
            return  # User canceled the file dialog

        try:
            # Read and parse the JSON file
            with open(file_path, "r") as file:
                scenario_data = json.load(file)

            # Clear existing outputs
            self.clear_node_outputs()
            self.output_text.delete(1.0, tk.END)

            # Get simulation duration from user input
            try:
                duration = int(self.duration_entry.get())
                if duration <= 0:
                    raise ValueError("Duration must be a positive integer.")
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid duration: {e}")
                return

            # Create nodes and add messages based on the scenario
            self.node_instances = []
            for node in self.nodes:
                node_id = node["node_id"]
                node_output = node["node_output"]
                can_node = Node(node_id, self.wire, node_output, self.node_text_widgets)

                # Add messages to the node if it exists in the scenario
                if str(node_id) in scenario_data:
                    for msg in scenario_data[str(node_id)]:
                        message = CANMessage(
                            msg["time"], node_id, msg["dlc"], msg["data"], msg["crc"], msg["selected_node"]
                        )
                        can_node.add_message(message)

                self.node_instances.append(can_node)

            # Add nodes to the wire and run the simulation
            for node in self.node_instances:
                self.wire.add_node(node)
            self.wire.time = 0
            self.wire.running_wire(duration)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load scenario: {e}")

    

if __name__ == "__main__":
    root = tk.Tk()
    app = CANNodeConfigurator(root)
    root.mainloop()