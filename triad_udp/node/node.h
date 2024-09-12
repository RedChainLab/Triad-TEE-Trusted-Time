class Node {
public:
    static Node* node;
    static Node* get_instance();
    static void destroy_instance();
};