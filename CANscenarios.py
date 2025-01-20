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
            else:
                self.wire.update_output(f"Error frame: Node {self.node_id} detected a CRC error.")
                #self.wire.insert_info(-1, f"Error frame: Node {self.node_id} detected a CRC error.")
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
        self.node_instances = []  # Initialize as an empty list
        master.title("CAN Node Configuration")
        self.node_text_widgets = {}

        # Configure grid weights for resizing
        master.grid_rowconfigure(0, weight=0)  # Top section (fixed height)
        master.grid_rowconfigure(1, weight=1)  # Middle section (takes all remaining vertical space)
        master.grid_rowconfigure(2, weight=0)  # Bottom section (fixed height)
        master.grid_columnconfigure(0, weight=1)  # Middle section takes full horizontal space

        # Top Section: Simulation Duration and Node Count
        self.top_frame = tk.Frame(master)
        self.top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # Simulation Duration
        self.duration_label = tk.Label(self.top_frame, text="Simulation Duration (ms):", font=("Arial", 10))
        self.duration_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.duration_entry = tk.Entry(self.top_frame, font=("Arial", 10), width=15)
        self.duration_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.duration_entry.insert(0, "100")  # Default value

        # Number of Nodes
        self.node_count_label = tk.Label(self.top_frame, text="Number of Nodes:", font=("Arial", 10))
        self.node_count_label.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.node_count_entry = tk.Entry(self.top_frame, font=("Arial", 10), width=15)
        self.node_count_entry.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.node_count_entry.insert(0, "3")  # Default value

        self.update_nodes_button = tk.Button(self.top_frame, text="Update Nodes", command=self.update_nodes)
        self.update_nodes_button.grid(row=0, column=4, padx=5, pady=5, sticky="w")

        # Middle Section: Scrollable Nodes Configuration
        self.middle_frame = tk.Frame(master)
        self.middle_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")  # Takes all remaining space

        # Canvas and Scrollbar for Nodes
        self.canvas = tk.Canvas(self.middle_frame)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.scrollbar = tk.Scrollbar(self.middle_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Frame inside the Canvas to hold the nodes
        self.nodes_frame = tk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.nodes_frame, anchor="nw")

        # Bind the canvas to update the scroll region when the nodes_frame size changes
        self.nodes_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        # Initialize nodes
        self.nodes = []
        self.update_nodes()

        # Bottom Section: Buttons
        self.bottom_frame = tk.Frame(master)
        self.bottom_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        self.configure_button = tk.Button(self.bottom_frame, text="Configure Nodes", command=self.configure_nodes)
        self.configure_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.load_scenario_button = tk.Button(self.bottom_frame, text="Load Scenario from File", command=self.load_scenario_from_file)
        self.load_scenario_button.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle the GUI closing event."""
        self.wire.clear_output_file()  # Clear the output.txt file
        self.master.destroy()

    def clear_node_outputs(self):
        """Clear the output text area for each node."""
        for node in self.nodes:
            node["node_output"].delete(1.0, tk.END)

    def create_node_frame(self, master, node_id):
        """Create a frame for a single node."""
        node_frame = tk.Frame(master, bd=2, relief=tk.GROOVE)
        node_frame.grid(row=node_id, column=0, padx=10, pady=10, sticky="ew")

        node_label = tk.Label(node_frame, text=f"Node {node_id + 1}", font=("Arial", 12))
        node_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        # Increase the height and width of the node output text area
        node_output = tk.Text(node_frame, height=10, width=80)  # Adjusted size (larger)
        node_output.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.node_text_widgets[node_id] = node_output

        messages_entries = []
        add_message_button = tk.Button(node_frame, text="Add Message", command=lambda: self.add_message_entry(node_frame, messages_entries, node_id))
        add_message_button.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        return {"node_id": node_id + 1, "node_frame": node_frame, "messages_entries": messages_entries, "node_output": node_output}

    def add_message_entry(self, node_frame, messages_entries, node_id):
        """Add a message entry to a node."""
        row = len(messages_entries) + 3
        entry_frame = tk.Frame(node_frame)
        entry_frame.grid(row=row, column=0, columnspan=6, pady=5, sticky="w")

        # Time field
        time_label = tk.Label(entry_frame, text="Time (s):", font=("Arial", 10))
        time_label.grid(row=0, column=0, padx=5, sticky="w")
        time_entry = tk.Entry(entry_frame, font=("Arial", 10), width=15)  # Increased width
        time_entry.grid(row=0, column=1, padx=5, sticky="w")

        # DLC field
        dlc_label = tk.Label(entry_frame, text="DLC:", font=("Arial", 10))
        dlc_label.grid(row=0, column=2, padx=5, sticky="w")
        dlc_entry = tk.Entry(entry_frame, font=("Arial", 10), width=10)  # Increased width
        dlc_entry.grid(row=0, column=3, padx=5, sticky="w")

        # Data field
        data_label = tk.Label(entry_frame, text="Data (bits):", font=("Arial", 10))
        data_label.grid(row=0, column=4, padx=5, sticky="w")
        data_entry = tk.Entry(entry_frame, font=("Arial", 10), width=25)  # Increased width
        data_entry.grid(row=0, column=5, padx=5, sticky="w")

        # CRC field
        crc_label = tk.Label(entry_frame, text="CRC (4-bit):", font=("Arial", 10))
        crc_label.grid(row=0, column=6, padx=5, sticky="w")
        crc_entry = tk.Entry(entry_frame, font=("Arial", 10), width=10)  # Increased width
        crc_entry.grid(row=0, column=7, padx=5, sticky="w")

        # Destination node dropdown
        selected_node_var = tk.StringVar()
        selected_node_var.set("1")  # Default to node 1
        node_dropdown = tk.OptionMenu(entry_frame, selected_node_var, *[str(i + 1) for i in range(len(self.nodes))])
        node_dropdown.grid(row=0, column=8, padx=5, sticky="w")

        # Store all input fields
        messages_entries.append({
            "time_entry": time_entry,
            "dlc_entry": dlc_entry,
            "data_entry": data_entry,
            "crc_entry": crc_entry,
            "selected_node_var": selected_node_var
        })

    def update_nodes(self):
        """Update the number of nodes based on user input."""
        try:
            num_nodes = int(self.node_count_entry.get())
            if num_nodes <= 0:
                raise ValueError("Number of nodes must be a positive integer.")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid number of nodes: {e}")
            return

        # Clear existing nodes
        for node in self.nodes:
            node["node_frame"].destroy()
        self.nodes.clear()
        self.node_text_widgets.clear()

        # Create new nodes
        self.nodes = [self.create_node_frame(self.nodes_frame, i) for i in range(num_nodes)]

        # Update the canvas scroll region
        self.nodes_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def configure_nodes(self):
        """Configure the nodes based on user input."""
        self.node_instances = []
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
                    crc = int(entry["crc_entry"].get())
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
        self.wire.running_wire(duration)

    def load_scenario_from_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Scenario File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not file_path:
            messagebox.showinfo("Info", "No file selected.")
            return

        if not file_path.endswith(".json"):
            messagebox.showerror("Error", "Invalid file type. Please select a JSON file.")
            return

        try:
            with open(file_path, "r") as file:
                scenario_data = json.load(file)
            
            # Validate node_count in JSON
            if "node_count" not in scenario_data or not isinstance(scenario_data["node_count"], int):
                raise ValueError("Invalid or missing 'node_count' in JSON file.")
            node_count = scenario_data["node_count"]

            # Update node count in GUI and reconfigure nodes
            self.node_count_entry.delete(0, tk.END)
            self.node_count_entry.insert(0, str(node_count))
            self.update_nodes()  # Re-create nodes based on new node_count

            self.wire = Wire()
            self.node_instances = []
            for node in self.nodes:
                node_id = node["node_id"]
                node_output = node["node_output"]
                can_node = Node(node_id, self.wire, node_output, self.node_text_widgets)

            for node_id_str, messages in scenario_data.get("nodes", {}).items():
                try:
                    node_id = int(node_id_str)
                    if not (1 <= node_id <= node_count):
                        raise ValueError(f"Node ID {node_id} exceeds the node count {node_count}.")
                    
                    # Create CANNode instance for this node
                    node_instance = Node(node_id, self.wire, self.node_text_widgets[node_id - 1], self.node_text_widgets)
                    self.node_instances.append(node_instance)

                    # Add messages to the corresponding node_instance
                    for msg in messages:
                        if not all(bit in '01' for bit in msg["data"]):
                            raise ValueError(f"Invalid data for Node {node_id}. Data should only contain bits (0 or 1).")
                        if len(msg["data"]) != msg["dlc"]:
                            raise ValueError(f"Invalid data length for Node {node_id}. DLC should match data length.")
                        if not (0 <= msg["crc"] <= 15):
                            raise ValueError(f"Invalid CRC for Node {node_id}. CRC must be a 4-bit value (0-15).")
                        
                        # Create a CANMessage and add it to the node instance
                        message = CANMessage(
                            time=msg["time"],
                            node_id=node_id,
                            dlc=msg["dlc"],
                            data=msg["data"],
                            crc=msg["crc"],
                            selected_node=msg["selected_node"]
                        )
                        node_instance.add_message(message)
                except ValueError as e:
                    messagebox.showerror("Error", str(e))
                    return
                except KeyError as e:
                    messagebox.showerror("Error", f"Missing key in scenario data: {e}")
                    return

            # Add all node instances to the wire
            for node_instance in self.node_instances:
                self.wire.add_node(node_instance)

            # Run the simulation
            self.wire.time = 0
            self.wire.running_wire(int(self.duration_entry.get()))  # Pass duration to the simulation method

        except FileNotFoundError:
            messagebox.showerror("Error", f"File not found: {file_path}")
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load scenario: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CANNodeConfigurator(root)
    root.mainloop()