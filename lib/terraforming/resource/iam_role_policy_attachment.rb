module Terraforming
  module Resource
    class IAMRolePolicyAttachment
      include Terraforming::Util

      def self.tf(client: Aws::IAM::Client.new)
        self.new(client).tf
      end

      def self.tfstate(client: Aws::IAM::Client.new)
        self.new(client).tfstate
      end

      def initialize(client)
        @client = client
      end

      def tf
        apply_template(@client, "tf/iam_role_policy_attachment")
      end

      def tfstate
        iam_role_policy_attachments.inject({}) do |resources, attachment|
          attributes = {
            "id" => iam_role_policy_attachment_id_of(attachment),
            "policy_arn" => attachment[1],
            "role" => attachment[0],
          }
          resources["aws_iam_role_policy_attachment.#{unique_name(attachment)}"] = {
            "type" => "aws_iam_role_policy_attachment",
            "primary" => {
              "id" => iam_role_policy_attachment_id_of(attachment),
              "attributes" => attributes
            }
          }

          resources
        end
      end

      private

      def unique_name(attachment)
        iam_role_policy_attachment_id_of(attachment).gsub(/[:\/\.]/, '_')
      end

      def iam_role_policy_attachment_id_of(attachment)
        "#{attachment[0]}:#{attachment[1].gsub(/.*policy\//, '')}"
      end

      def iam_roles
        @client.list_roles.map(&:roles).flatten
      end

      def iam_role_policy_names_in(role)
        resp = @client.list_attached_role_policies(role_name: role.role_name)
        policy_names = []
        resp.attached_policies.each do |pol|
          policy_names.push(pol.policy_arn)
        end
        return policy_names
      end

      def iam_role_policy_attachments
        rpa_map = []
        iam_roles.map do |role|
          iam_role_policy_names_in(role).map { |policy_name| rpa_map.push([role.role_name, policy_name]) }
        end.flatten
        return rpa_map
      end
    end
  end
end
