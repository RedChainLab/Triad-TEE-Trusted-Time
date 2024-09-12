#include <iostream>

#include "node.h"

Node* Node::node = nullptr;

Node* Node::get_instance()
{
    if (node == nullptr) 
    {
        node = new Node();
        std::cout << "Node instance created: " << node << std::endl;
    }
    else
    {
        std::cout << "Node instance already exists: " << node << std::endl;
    }
    return node;
}

void Node::destroy_instance()
{
    if (node != nullptr) 
    {
        std::cout << "Destroying node instance: " << node << std::endl;
        delete node;
        node = nullptr;
    }
    else
    {
        std::cout << "Node instance does not exist: " << node << std::endl;
    }
}