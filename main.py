import json
import sys
from icecream import ic

class MitreAttckJsonParser:
    # Create a dictionary with all possible types of input as keys (name/ID) and stores the required info for the given keys as the values (description, associated tactics, etc)
    def create_enterprise_table(self, file_path: str):
        enterprise_table = {}
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        i = 0
        parsing = True  # parses around 100,000 lines till the last technique 'COR_PROFILER'

        while parsing:
            # If the object is a tactic, add 2 keys to the dictionary - its ID and name with the required values against it.
            # Eg:- A name is the key and its ID (name instead of ID when ID is key) and description are stored as its value as a list.
            if (
                id := (data["objects"][i]["external_references"][0]["external_id"])
            ).startswith("TA0"):
                description = data["objects"][i]["description"]
                name = data["objects"][i]["name"].title()
                url = data["objects"][i]["external_references"][0]["url"]
                values = [description, name, url]
                enterprise_table[id] = values
                values = [description, id, url]
                enterprise_table[name] = values

            # Same logic but an additional list element is added to the list of values against the key to list the tactics associated with the technique.
            # ID: [description, name, [tactic1, tactic2, tactic3]] is the format.
            elif (
                id := (data["objects"][i]["external_references"][0]["external_id"])
            ).startswith("T1") and data["objects"][i]["type"] == "attack-pattern":
                description = data["objects"][i]["description"]
                name = data["objects"][i]["name"].title()
                url = data["objects"][i]["external_references"][0]["url"]
                tactics = []

                for j in data["objects"][i]["kill_chain_phases"]:
                    tactics.append(j["phase_name"])

                values = [description, name, url, tactics]
                enterprise_table[id] = values
                values = [description, id, url, tactics]
                enterprise_table[name] = values

            if data["objects"][i]["name"] == "COR_PROFILER":
                parsing = False

            i += 1
        self.enterprise_table = enterprise_table

    def create_mobile_table(self, file_path: str):
        mobile_table = {}
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        i = 0
        parsing = True  # parses around 100,000 lines till the last technique 'Suppress Application Icon'

        while parsing:
            if data["objects"][i].get("revoked") != True:
                if (
                    id := (data["objects"][i]["external_references"][0]["external_id"])
                ).startswith("TA0"):
                    description = data["objects"][i]["description"]
                    name = data["objects"][i]["name"].title()
                    url = data["objects"][i]["external_references"][0]["url"]
                    values = [description, name, url]
                    mobile_table[id] = values
                    values = [description, id, url]
                    mobile_table[name] = values

                elif (
                    id := (data["objects"][i]["external_references"][0]["external_id"])
                ).startswith("T1") and data["objects"][i]["type"] == "attack-pattern":
                    description = data["objects"][i]["description"]
                    name = data["objects"][i]["name"].title()
                    url = data["objects"][i]["external_references"][0]["url"]
                    tactics = []

                    for j in data["objects"][i]["kill_chain_phases"]:
                        tactics.append(j["phase_name"])

                    values = [description, name, url, tactics]
                    mobile_table[id] = values
                    values = [description, id, url, tactics]
                    mobile_table[name] = values

                if data["objects"][i]["name"] == "Suppress Application Icon":
                    parsing = False

            i += 1
        self.mobile_table = mobile_table

    def get_enterprise_table(self):
        return self.enterprise_table

    def get_mobile_table(self):
        return self.mobile_table

    # The names are stored as titles (this is cleaner while displaying) so we use the title() function while finding our required key.
    def input_query(self):
        self.query_data = None
        self.query = input("Enter the Tactic or Technique ID/Name or 'exit' to exit: ").title()
        
        if self.query == "Exit":
            sys.exit()
        
        if len(self.query) == 6:
            self.query = self.query.upper()

        # from here
        self.domains = []
        if self.query in self.enterprise_table:
            self.query_data = self.enterprise_table.get(self.query)
            self.domains.append("Enterprise")

        if self.query in self.mobile_table:
            self.query_data = self.mobile_table.get(self.query)
            self.domains.append("Mobile")

        if self.query_data == None:
            print("Tactic/Technique not found. Enter a valid Tactic or Technique: ")
            self.input_query()

    def get_domains(self):
        return self.domains

    def display_domains(self):
        print("Domain(s): ", end="")
        for i in self.get_domains():
            print(i.title(), end="")
            if i != self.get_domains()[-1]:
                print(", ", end="")
        print()

    def get_query_data(self):
        return self.query_data

    def search_query(self):
        # Techniques have 3 values (desc, ID/name, associated tactics) while tactics have 2 (name/ID, desc)
        if "Enterprise" in self.domains:
            print("Enterprise Domain Data:- ")
            self.table = self.enterprise_table
            
            if self.query_data:
                if len(self.query_data) == 3:
                    tactic = Tactics()
                    tactic.findID(self.query, self.table) if self.query.startswith(
                        "TA0"
                    ) else tactic.findNAME(self.query.title(), self.table)
                    tactic.displayInfo()

                else:
                    technique = Techniques()
                    technique.findID(self.query, self.table) if self.query.startswith(
                        "T1"
                    ) else technique.findNAME(self.query.title(), self.table)
                    technique.displayInfo()

        if "Mobile" in self.domains:
            print("Mobile Domain Data:- ")
            self.table = self.mobile_table

            if self.query_data:
                if len(self.query_data) == 3:
                    tactic = Tactics()
                    tactic.findID(self.query, self.table) if self.query.startswith(
                        "TA0"
                    ) else tactic.findNAME(self.query.title(), self.table)
                    tactic.displayInfo()

                else:
                    technique = Techniques()
                    technique.findID(self.query, self.table) if self.query.startswith(
                        "T1"
                    ) else technique.findNAME(self.query.title(), self.table)
                    technique.displayInfo()


# Extract data for a Tactic and display
class Tactics:
    def findID(self, tactic_id, table: dict):
        self.id = tactic_id
        self.description = table[self.id][0]
        self.name = table[self.id][1]
        self.url = table[self.id][2]

    def findNAME(self, tactic_name, table: dict):
        self.name = tactic_name
        self.description = table[self.name][0]
        self.id = table[self.name][1]
        self.url = table[self.id][2]

    def getId(self):
        return self.id

    def getName(self):
        return self.name

    def getDescription(self):
        return self.description

    def getURL(self):
        return self.url

    def displayInfo(self):
        print("[Tactic Details]")
        print("ID: ", self.getId())
        print("Name: ", self.getName())
        print("Description: ", self.getDescription())
        print("URL: ", self.getURL())


# Extract data for a Technique and display
class Techniques:
    def findID(self, technique_id, table: dict):
        self.id = technique_id
        self.description = table[self.id][0]
        self.name = table[self.id][1]
        self.url = table[self.id][2]
        self.tacticList = table[self.id][3]

    def findNAME(self, technique_name, table: dict):
        self.name = technique_name
        self.description = table[self.name][0]
        self.id = table[self.name][1]
        self.url = table[self.id][2]
        self.tacticList = table[self.name][3]

    def getId(self):
        return self.id

    def getName(self):
        return self.name

    def getDescription(self):
        return self.description

    def getURL(self):
        return self.url

    def getTacticList(self):
        return self.tacticList

    def displayInfo(self):
        print("[Technique Details]")
        print("ID: ", self.getId())
        print("Name: ", self.getName())
        print("Description: ", self.getDescription())
        print("URL: ", self.getURL())
        print("Associated Tactic(s): ", end="")

        for i in self.getTacticList():
            print(i.title(), end="")
            if i != self.getTacticList()[-1]:
                print(", ", end="")       
        print("\n")


def main():
    mitreDataRetriever = MitreAttckJsonParser()
    mitreDataRetriever.create_enterprise_table("enterprise-attack.json")
    mitreDataRetriever.create_mobile_table("mobile-attack.json")
    while True:
        mitreDataRetriever.input_query()
        mitreDataRetriever.display_domains()
        mitreDataRetriever.search_query()


if __name__ == "__main__":
    main()
